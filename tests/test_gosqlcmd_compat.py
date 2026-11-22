"""Offline parse test: rows_of() against go-sqlcmd output (AZ-1369).

No go-sqlcmd binary is installed on the build host, so the sample output below is
built to the byte layout of go-sqlcmd's default formatter at commit
a97013a80b01f3aaac4fb17e9ef422283f15cb2f (pkg/sqlcmd/format.go, pkg/sqlcmd/sqlcmd.go):

- AddRow: values joined by the one-byte SQLCMDCOLSEP, then SqlcmdEol ("\\n" on Linux).
  With -W (TrimSpaces) no padding is added. With -h -1 no header lines are printed.
- EndResultSet: one blank line.
- MsgRowsAffected: "(1 row affected)" or "(N rows affected)" on its own line.
- MsgNotice (server PRINT/warnings): the message text on its own line, on stdout.
- Errors without -r go to stdout too: "Msg N, Level L, State S, Server X, Line n".

Upstream's own tests assert this exact shape, for example
pkg/sqlcmd/sqlcmd_test.go: "1" + SqlcmdEol + SqlcmdEol + "(1 row affected)" + SqlcmdEol.
This proves the parser accepts that layout. It does not prove a real go-sqlcmd run.
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sqlhc.runner import SEP, rows_of  # noqa: E402

EOL = "\n"


def go_output(rows, notices=(), crlf=False):
    """Build stdout the way go-sqlcmd -W -h -1 -s SEP prints one result set."""
    eol = "\r\n" if crlf else EOL
    out = "".join(SEP.join(r) + eol for r in rows)
    out += eol                                           # EndResultSet
    out += "".join(n + eol for n in notices)             # notices read after the rows
    n = len(rows)
    out += ("(1 row affected)" if n == 1 else f"({n} rows affected)") + eol
    return out


class GoSqlcmdLayoutTests(unittest.TestCase):
    def test_upstream_literal_single_value(self):
        # Exact bytes asserted by go-sqlcmd's own test suite.
        self.assertEqual(rows_of("1" + EOL + EOL + "(1 row affected)" + EOL, 1), [["1"]])

    def test_privilege_probe_row(self):
        vals = ["0"] * 12
        self.assertEqual(rows_of(go_output([vals]), 12), [vals])

    def test_many_rows_and_plural_count(self):
        rows = [["model", "FULL", "NEVER"], ["Shop", "SIMPLE", "2026-11-19 01:25:00"]]
        self.assertEqual(rows_of(go_output(rows), 3), rows)

    def test_zero_rows(self):
        self.assertEqual(rows_of(go_output([]), 2), [])

    def test_null_and_decimal_text(self):
        # go-sqlcmd prints SQL NULL as "NULL" and decimal(12,1) as plain digits, like ODBC.
        rows = [["CXPACKET", "12.5", "NULL"]]
        self.assertEqual(rows_of(go_output(rows), 3), rows)

    def test_warning_notice_is_not_a_row(self):
        out = go_output([["a", "b"]], notices=["Warning: Null value is eliminated by an aggregate or other SET operation."])
        self.assertEqual(rows_of(out, 2), [["a", "b"]])

    def test_windows_line_endings(self):
        # On Windows go-sqlcmd uses "\r\n" as SqlcmdEol.
        rows = [["a", "b"], ["c", "d"]]
        self.assertEqual(rows_of(go_output(rows, crlf=True), 2), rows)

    def test_name_with_line_break_is_refused(self):
        # ControlIgnore is the default: a newline inside a value is printed as-is,
        # so the row count check must still catch the forged extra line.
        d = [0]
        out = go_output([["x\nfake", "HIGH"]])
        self.assertEqual(rows_of(out, 2, d), [])
        self.assertEqual(d[0], 2)

    def test_non_warning_notice_after_count_disables_count_check(self):
        # Known gap (same in ODBC): a non-"Warning:" message printed after the count line
        # hides the count, so rows_of falls back to column-count parsing only. Both the
        # message and the stranded count line are counted as dropped: the check is
        # reported as partly unparsable, never silently clean.
        out = go_output([["a", "b"]]) + "Some server message" + EOL
        d = [0]
        self.assertEqual(rows_of(out, 2, d), [["a", "b"]])
        self.assertEqual(d[0], 2)


if __name__ == "__main__":
    unittest.main()
