"""Offline tests: no SQL Server needed. Run: python3 -m unittest discover -s tests"""
import os
import re
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sqlhc.checks import DB_CHECKS, DB_PRIV_PROBE, PRIV_PROBE, SERVER_CHECKS  # noqa: E402
from sqlhc.redact import redact  # noqa: E402
from sqlhc.summary import AREA_RANK, IMPACT, top_findings  # noqa: E402
from sqlhc.runner import GuardError, collect, esc, findings_of, guard, md_table, render_markdown, rows_of  # noqa: E402

ALL = SERVER_CHECKS + DB_CHECKS + [PRIV_PROBE, DB_PRIV_PROBE]


class GuardTests(unittest.TestCase):
    def test_every_shipped_check_passes_the_guard(self):
        for chk in ALL:
            guard(chk["sql"])

    def test_ids_unique_and_fields_present(self):
        ids = [c["id"] for c in ALL]
        self.assertEqual(len(ids), len(set(ids)))
        for c in SERVER_CHECKS + DB_CHECKS:
            self.assertIn(c.get("severity", "info"), ("high", "medium", "low", "info"))
            if c.get("severity", "info") != "info":
                self.assertTrue(c.get("fix"), c["id"])

    def test_guard_refuses_writes_and_exec(self):
        bad = [
            "UPDATE t SET a = 1",
            "DELETE FROM t",
            "SELECT 1; DROP TABLE t",
            "SELECT * INTO t2 FROM t",
            "WITH x AS (SELECT 1 a) DELETE FROM t",
            "SELECT 1 EXEC sp_configure",
            "SELECT * FROM OPENROWSET('SQLNCLI', 'x', 'SELECT 1')",
            "EXEC xp_cmdshell 'dir'",
            "SELECT 1 WAITFOR DELAY '00:01'",
            "DBCC CHECKDB",
            "USE otherdb SELECT 1",
        ]
        for sql in bad:
            with self.assertRaises(GuardError, msg=sql):
                guard(sql)

    def test_guard_refuses_known_bypass_shapes(self):
        bad = [
            "SELECT 1\nGO\ndbo.some_proc",              # GO batch, bare proc call
            "SELECT 1\n:!! id",                         # sqlcmd shell command
            "SELECT 1\n:r other.sql",                   # sqlcmd include
            "SELECT 1\n!! id",
            "SELECT 1 /* ' */ DROP TABLE t --'",         # comment/literal desync
            "SELECT 1 -- x",
            "SELECT 1 /* x */",
            "SELECT 1 CHECKPOINT",
            "SELECT 1 WRITETEXT t.c @p 'x'",
            "SELECT 1 RECEIVE * FROM q",
            "SELECT 1 DISABLE TRIGGER tr ON t",
            "SELECT 1 RAISERROR('x', 10, 1) WITH LOG",
            "SELECT 1 BEGIN TRAN",
            "SELECT * FROM t WITH (TABLOCKX)",
            "SELECT NEXT VALUE FOR dbo.seq",
            "SELECT '$(HC_PW)'".replace("'", ""),        # sqlcmd variable outside a literal
            "SELECT 1 SET NOCOUNT OFF",
            "SELECT 'unterminated",
            "SELECT 1 ;",
            ";;SELECT 1",
        ]
        for sql in bad:
            with self.assertRaises(GuardError, msg=sql):
                guard(sql)

    def test_guard_refuses_digit_glued_and_quote_desync(self):
        bad = [
            "SELECT 1DROP TABLE t",                     # T-SQL reads 1 then DROP
            "SELECT 0x1DELETE FROM t",
            "SELECT 1.5EXEC sp_who",
            "SELECT 2xp_cmdshell",
            "SELECT [a'] DROP TABLE t --']",           # quote inside brackets
            "SELECT \"a'\" DROP TABLE t",               # quote inside double quotes
            "SELECT [a]] DROP TABLE t",                 # escaped ]] then unbalanced
            "SELECT [unterminated",
            "SELECT \"unterminated",
        ]
        for sql in bad:
            with self.assertRaises(GuardError, msg=sql):
                guard(sql)

    def test_guard_ignores_keywords_inside_string_literals(self):
        guard("SELECT name FROM sys.configurations WHERE name = 'backup compression default'")
        guard("SELECT 1 WHERE 'it''s a DROP' = 'x'")
        guard("SELECT [DROP 'x] FROM t")
        guard("SELECT \"DELETE\" FROM t WHERE [a]]b] = N'x'")
        guard("SELECT @drop_count, #exec_tmp.a, create_date FROM t")


class RedactTests(unittest.TestCase):
    CASES = [
        ("SELECT * FROM dbo.Customers WHERE Email = 'alice@example.com'",
         "SELECT * FROM dbo.Customers WHERE Email = '?'"),
        ("UPDATE dbo.Cards SET Pan = 1234567890123 WHERE Id = 7",
         "UPDATE dbo.Cards SET Pan = ? WHERE Id = ?"),
        ("SELECT Name FROM dbo.People WHERE LastName = N'O''Brien' AND Age > 42.5",
         "SELECT Name FROM dbo.People WHERE LastName = '?' AND Age > ?"),
        ("SELECT TOP (5) col1, [Order 2024] FROM t2 WHERE x = 0x1F2E",
         "SELECT TOP (?) col1, [Order 2024] FROM t2 WHERE x = 0x?"),
        ("SELECT a FROM t WHERE ssn = '123-45-67",  # cut off inside a literal
         "SELECT a FROM t WHERE ssn = '?'"),
        ("SELECT 1 -- note from bob@example.org\nFROM t", "SELECT ? FROM t"),
        ("SELECT /* token=abc123 */ \"Col 9\" FROM t WHERE d > '2026-01-01' AND v = 1e5",
         "SELECT \"?\" FROM t WHERE d > '?' AND v = ?"),
        ("SELECT a FROM t WHERE b = 0X1F2E3D", "SELECT a FROM t WHERE b = 0x?"),
        ("SELECT a FROM t WHERE b = \"secret value\"", "SELECT a FROM t WHERE b = \"?\""),
        # T-SQL block comments nest: text after the inner */ is still comment
        ("SELECT 1 /* a /* b */ x=ann@x.com */ FROM t", "SELECT ? FROM t"),
        ("SELECT /* 1 /* 2 /* 3 */ ann@x.com */ 4455667788 */ c FROM t", "SELECT c FROM t"),
        ("SELECT c FROM t /* a /* b */ cut off ann@x.com 998877", "SELECT c FROM t"),
        ("SELECT '/* not a comment' AS c, d FROM t WHERE e = 123456",
         "SELECT '?' AS c, d FROM t WHERE e = ?"),
        ("SELECT [a/*b] FROM t WHERE x = 'bob@y.org' -- /* tail", "SELECT [a/*b] FROM t WHERE x = '?'"),
        ("SELECT 1 /* -- dash in comment ann@x.com */ FROM t", "SELECT ? FROM t"),
        ("SELECT a */ FROM t WHERE b = 778899", "SELECT a */ FROM t WHERE b = ?"),
    ]

    def test_cases(self):
        for src, want in self.CASES:
            self.assertEqual(redact(src), want, src)

    def test_no_leak(self):
        for src, _ in self.CASES:
            got = redact(src)
            stripped = re.sub(r"\[[^\]]*\]|\"[^\"]*\"|@\w+|\b[A-Za-z_]\w*\b", "", got)
            self.assertIsNone(re.search(r"\d{3,}|[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+\.", stripped), got)


class ReportTests(unittest.TestCase):
    def fake(self):
        server = {c["id"]: {"rows": []} for c in SERVER_CHECKS}
        server["S01"] = {"rows": [["16.0.1", "RTM", "Developer", "4", "8000", "12"]]}
        server["S04"] = {"rows": [["Shop", "AUTO_CLOSE ON; "]]}
        server["S10"] = {"rows": [["sa"]]}
        db = {c["id"]: {"rows": []} for c in DB_CHECKS}
        db["D01"] = {"rows": [["dbo.Lines", "400000"]]}
        return {"started": "2026-01-01T00:00:00", "secs": 1.0, "probe": {}, "powerful": [],
                "dbs": ["Shop"], "skipped_dbs": [], "results": {"server": server, "db": {"Shop": db}},
                "full_query_text": False}

    def test_findings_sorted_by_severity(self):
        f = findings_of(self.fake())
        self.assertEqual([x[0]["id"] for x in f], ["S04", "D01", "S10"])

    def test_report_has_caveats(self):
        md, counts, errors = render_markdown(self.fake())
        self.assertEqual(counts, {"high": 1, "medium": 1, "low": 1})
        self.assertIn("AUTO_CLOSE is ON for Shop", md)
        self.assertIn("uptime is 12 h", md)
        self.assertIn("literals redacted", md)

    def test_every_check_has_one_impact_line(self):
        ids = {c["id"] for c in SERVER_CHECKS + DB_CHECKS}
        self.assertEqual(set(IMPACT), ids)
        self.assertEqual(len(IMPACT), 21)
        for cid, text in IMPACT.items():
            self.assertTrue(text.endswith("."), cid)
            self.assertNotIn("\n", text, cid)
            self.assertEqual(text.count(". "), 0, cid)    # one sentence
            self.assertLessEqual(len(text), 220, cid)
        for c in SERVER_CHECKS + DB_CHECKS:
            self.assertIn(c["area"], AREA_RANK, c["id"])

    def test_area_rank_order(self):
        order = sorted(AREA_RANK, key=lambda a: AREA_RANK[a])
        self.assertEqual(order[:4], ["Recoverability", "Security", "Configuration", "Performance"])

    def test_exec_summary_ranks_area_before_severity(self):
        md, _, _ = render_markdown(self.fake())
        head = md.split("## Executive summary", 1)[1].split("## Summary", 1)[0]
        lines = [x for x in head.splitlines() if x[:2] in ("1.", "2.", "3.")]
        self.assertEqual(len(lines), 3)
        # Security (low) outranks Configuration (high), which outranks Schema (medium).
        self.assertIn("'sa' login enabled", lines[0])
        self.assertIn("Risky database options", lines[1])
        self.assertIn("Large heaps", lines[2])
        self.assertIn(IMPACT["S10"], lines[0])
        self.assertLess(md.index("## Executive summary"), md.index("## Summary"))

    def test_exec_summary_dedupes_and_caps_at_three(self):
        data = self.fake()
        data["results"]["server"]["S02"] = {"rows": [["master", "SIMPLE", "NEVER"]]}
        data["dbs"].append("Shop2")
        db2 = {c["id"]: {"rows": []} for c in DB_CHECKS}
        db2["D01"] = {"rows": [["dbo.X", "20000"]]}
        data["results"]["db"]["Shop2"] = db2
        top = top_findings(findings_of(data))
        self.assertEqual([f[0]["id"] for f in top], ["S02", "S10", "S04"])
        self.assertEqual([f[0]["id"] for f in top_findings(findings_of(data), n=5)],
                         ["S02", "S10", "S04", "D01"])
        md, _, _ = render_markdown(data)
        self.assertIn("1. **Databases without a recent full backup (7 days)** (Recoverability, high", md)

    def test_exec_summary_counts_places_for_repeated_check(self):
        data = self.fake()
        data["results"]["server"]["S10"] = {"rows": []}
        data["results"]["server"]["S04"] = {"rows": []}
        data["dbs"].append("Shop2")
        db2 = {c["id"]: {"rows": []} for c in DB_CHECKS}
        db2["D01"] = {"rows": [["dbo.X", "20000"]]}
        data["results"]["db"]["Shop2"] = db2
        md, _, _ = render_markdown(data)
        self.assertIn("(Schema, medium, 2 places)", md)

    def test_exec_summary_with_no_findings_and_errors(self):
        data = self.fake()
        for cid in ("S04", "S10"):
            data["results"]["server"][cid] = {"rows": []}
        data["results"]["db"]["Shop"]["D01"] = {"rows": [], "error": "denied"}
        md, _, errors = render_markdown(data)
        self.assertEqual(len(errors), 1)
        self.assertIn("No findings. Nothing in this run needs action", md)
        self.assertIn("1 check(s) could not run, so this summary may miss risks", md)

    def test_exec_summary_escapes_place_name(self):
        md, _, _ = render_markdown(self._with_db("<b>x</b>"))
        head = md.split("## Executive summary", 1)[1].split("## Summary", 1)[0]
        self.assertNotIn("<b>", head)

    def test_rows_of_splits_on_unit_separator(self):
        self.assertEqual(rows_of("a\x1fb\n\nc\n", 2), [["a", "b"]])

    def test_rows_of_counts_dropped_lines(self):
        d = [0]
        self.assertEqual(rows_of("a\x1fb\nodd\nx\x1fy\x1fz\n", 2, d), [["a", "b"]])
        self.assertEqual(d[0], 2)

    def test_rows_of_uses_sqlcmd_rowcount(self):
        self.assertEqual(rows_of("a\x1fb\nc\x1fd\n\n(2 rows affected)\n", 2), [["a", "b"], ["c", "d"]])
        self.assertEqual(rows_of("a\x1fb\n\n(1 row affected)\n", 2), [["a", "b"]])
        self.assertEqual(rows_of("Warning: Null value is eliminated by an aggregate.\n"
                                 "a\x1fb\n(1 row affected)\n", 2), [["a", "b"]])

    def test_rows_of_refuses_a_forged_row(self):
        # One real row whose first value holds a line break plus a fake second row.
        out = "x\x1fy\nfake\x1fHIGH\n\n(1 row affected)\n"
        d = [0]
        self.assertEqual(rows_of(out, 2, d), [])
        self.assertEqual(d[0], 2)
        # A forged "(N rows affected)" inside a name is not the last line, so it cannot help.
        out = "(2 rows affected)\nfake\x1fHIGH\nreal\x1fz\n\n(1 row affected)\n"
        self.assertEqual(rows_of(out, 2), [])

    def test_server_text_is_inert_in_markdown_and_html(self):
        evil = ["<img src=x onerror=alert(1)>", "![t](http://tracker.example/p.png)", "[x](javascript:alert(1))",
                "a|b", "`code`", "line\nbreak"]
        out = md_table(["name"], [[e] for e in evil])
        self.assertNotIn("<img", out)
        self.assertNotIn("](", out)
        self.assertNotIn("![", out.replace("\\!\\[", ""))
        self.assertIn("| line break |", out)          # newline flattened, row not split
        self.assertEqual(len(out.splitlines()), 2 + len(evil))
        self.assertEqual(esc("a|b"), "a\\|b")
        md, _, _ = render_markdown(self._with_db("<b>x</b>"))
        self.assertNotIn("<b>", md)

    def test_autolinks_and_bidi_are_broken(self):
        for raw in ("http://tracker.example/p", "HTTPS://x.example", "www.evil.example", "WWW.evil.example",
                    "bob@example.org", "mailto:a@b.c", "xmpp:a@b.c"):
            out = esc(raw)
            self.assertNotIn("://", out, raw)
            self.assertIsNone(re.search(r"(?i)www\.", out), raw)
            self.assertNotRegex(out, r"@[A-Za-z0-9]", raw)
        self.assertEqual(esc("10:00"), "10:00")
        self.assertEqual(esc("SELECT @x = 1"), "SELECT @x = 1")
        self.assertEqual(esc("abc\u202edef"), "abc\ufffddef")
        self.assertNotIn("\u2066", esc("x\u2066y"))

    def _with_db(self, name):
        d = self.fake()
        d["dbs"] = [name]
        d["results"]["db"] = {name: d["results"]["db"]["Shop"]}
        return d


class FakeConn:
    """Answers the probes with canned sqlcmd output; records every query."""
    def __init__(self, server_probe, db_probe="0", dbs=("Shop",)):
        self.server_probe, self.db_probe, self.dbs, self.seen = server_probe, db_probe, dbs, []

    def query(self, sql, db="master"):
        guard(sql)
        self.seen.append((db, sql[:30]))
        if sql == PRIV_PROBE["sql"]:
            return 0, self.server_probe, ""
        if sql == DB_PRIV_PROBE["sql"]:
            return 0, self.db_probe, ""
        if "FROM sys.databases WHERE database_id > 4 AND state = 0" in sql:
            return 0, "\n".join(self.dbs) + "\n", ""
        return 0, "", ""


class ProbeTests(unittest.TestCase):
    N = len(PRIV_PROBE["cols"])
    ND = len(DB_PRIV_PROBE["cols"])

    def ok_server(self):
        return "\x1f".join(["0"] * (self.N - 2) + ["1", "1"]) + "\n"

    def ok_db(self):
        return "\x1f".join(["0"] * self.ND) + "\n"

    def test_probe_fails_closed_on_empty_output(self):
        with self.assertRaises(SystemExit):
            collect(FakeConn(""))

    def test_probe_fails_closed_on_garbage(self):
        with self.assertRaises(SystemExit):
            collect(FakeConn("\x1f".join(["NULL"] * self.N) + "\n"))

    def test_server_power_refused(self):
        row = ["1"] + ["0"] * (self.N - 1)
        with self.assertRaises(SystemExit):
            collect(FakeConn("\x1f".join(row) + "\n", self.ok_db()))

    def test_db_owner_refused_before_any_db_check(self):
        row = ["1"] + ["0"] * (self.ND - 1)
        conn = FakeConn(self.ok_server(), "\x1f".join(row) + "\n")
        with self.assertRaises(SystemExit) as cm:
            collect(conn)
        self.assertIn("Shop (db_owner)", str(cm.exception))
        db_checks_run = [s for d, s in conn.seen if d == "Shop" and s != DB_PRIV_PROBE["sql"][:30]]
        self.assertEqual(db_checks_run, [])

    def test_db_probe_failure_counts_as_powerful(self):
        with self.assertRaises(SystemExit):
            collect(FakeConn(self.ok_server(), ""))

    def test_least_privilege_login_runs(self):
        data = collect(FakeConn(self.ok_server(), self.ok_db()))
        self.assertEqual(data["dbs"], ["Shop"])
        self.assertEqual(data["powerful"], [])

    def test_system_databases_are_probed(self):
        conn = FakeConn(self.ok_server(), self.ok_db())
        collect(conn)
        probed = [d for d, s in conn.seen if s == DB_PRIV_PROBE["sql"][:30]]
        self.assertEqual(probed, ["master", "msdb", "model", "Shop"])

    def test_msdb_power_refused(self):
        class MsdbAgent(FakeConn):
            def query(self, sql, db="master"):
                if sql == DB_PRIV_PROBE["sql"] and db == "msdb":
                    guard(sql)
                    row = ["0"] * (ProbeTests.ND - 2) + ["1", "0"]
                    return 0, "\x1f".join(row) + "\n", ""
                return super().query(sql, db)
        with self.assertRaises(SystemExit) as cm:
            collect(MsdbAgent(self.ok_server(), self.ok_db()))
        self.assertIn("msdb (msdb_agent_mail_ssis_role)", str(cm.exception))

    def test_server_probe_lists_new_permissions(self):
        for col in ("alter_trace", "alter_any_event_session", "unsafe_assembly", "authenticate_server"):
            self.assertIn(col, PRIV_PROBE["cols"])
        self.assertEqual(PRIV_PROBE["sql"].count("HAS_PERMS_BY_NAME") + 1, len(PRIV_PROBE["cols"]))
        self.assertEqual(DB_PRIV_PROBE["sql"].count("HAS_PERMS_BY_NAME") + 7, len(DB_PRIV_PROBE["cols"]))


class IoLatencyTests(unittest.TestCase):
    """S21: per-file I/O latency from sys.dm_io_virtual_file_stats."""
    S21 = next(c for c in SERVER_CHECKS if c["id"] == "S21")

    def test_shape_and_guard(self):
        c = self.S21
        guard(c["sql"])
        self.assertEqual(c["severity"], "medium")
        self.assertTrue(c["fix"])
        # One output column per SELECT expression (7) and 7 names.
        self.assertEqual(len(c["cols"]), 7)
        self.assertIn("sys.dm_io_virtual_file_stats(NULL, NULL)", c["sql"])

    def test_reads_only_view_server_state_objects(self):
        sql = self.S21["sql"]
        objects = set(re.findall(r"\bsys\.\w+", sql))
        self.assertEqual(objects, {"sys.dm_io_virtual_file_stats", "sys.master_files"})
        # No physical paths in reports (drive layout is sensitive).
        self.assertNotIn("physical_name", sql)

    def test_thresholds_and_divide_by_zero_safe(self):
        sql = self.S21["sql"]
        self.assertIn("num_of_reads >= 1000 AND vfs.io_stall_read_ms >= 20 * vfs.num_of_reads", sql)
        self.assertIn("num_of_writes >= 1000 AND vfs.io_stall_write_ms >= 20 * vfs.num_of_writes", sql)
        self.assertEqual(sql.count("NULLIF("), 2)
        # A file busy on one side only shows 0 for the other average, not NULL.
        self.assertEqual(sql.count("ISNULL(CAST(1.0 * vfs.io_stall_"), 2)

    def test_lab_output_parses_to_seven_columns(self):
        # Shape of real sqlcmd output from the SQL Server 2022 lab (zero-threshold run).
        out = ("master\x1fmaster\x1fROWS\x1f72\x1f.6\x1f162\x1f.5\n"
               "DemoShop\x1fDemoShop_log\x1fLOG\x1f30\x1f.3\x1f2210\x1f.1\n\n(2 rows affected)\n")
        d = [0]
        rows = rows_of(out, len(self.S21["cols"]), d)
        self.assertEqual(d[0], 0)
        self.assertEqual(rows[1], ["DemoShop", "DemoShop_log", "LOG", "30", ".3", "2210", ".1"])

    def test_finding_renders_in_report(self):
        server = {c["id"]: {"rows": []} for c in SERVER_CHECKS}
        server["S01"] = {"rows": [["16.0.1", "RTM", "Developer", "4", "8000", "300"]]}
        server["S21"] = {"rows": [["DemoShop", "DemoShop_log", "LOG", "12", "0.4", "48210", "27.3"]]}
        data = {"started": "2026-01-01T00:00:00", "secs": 1.0, "probe": {}, "powerful": [],
                "dbs": [], "skipped_dbs": [], "results": {"server": server, "db": {}},
                "full_query_text": False}
        self.assertEqual([f[0]["id"] for f in findings_of(data)], ["S21"])
        md, counts, _ = render_markdown(data)
        self.assertEqual(counts, {"high": 0, "medium": 1, "low": 0})
        self.assertIn("S21 [MEDIUM] Slow file I/O", md)
        self.assertIn("27.3", md)


class GrantReaderScriptTests(unittest.TestCase):
    """sql/grant-reader.sql must refuse a pre-existing hc_reader before it grants anything."""

    def setUp(self):
        path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "sql", "grant-reader.sql")
        with open(path, encoding="utf-8") as f:
            self.sql = f.read()
        self.code = "\n".join(l.split("--", 1)[0] for l in self.sql.splitlines())

    def test_single_batch(self):
        # One batch: THROW then aborts the rest even without sqlcmd -b.
        go = [l for l in self.code.splitlines() if l.strip().upper() == "GO"]
        self.assertEqual(len(go), 1)
        self.assertEqual(self.code.rstrip().splitlines()[-1].strip().upper(), "GO")
        self.assertNotRegex(self.code, r"(?im)^\s*USE\s")

    def test_refuses_existing_login_and_msdb_user_first(self):
        first_write = min(self.code.index(k) for k in ("CREATE LOGIN", "GRANT ", "EXEC ("))
        login = re.search(r"IF SUSER_ID\('hc_reader'\) IS NOT NULL\s+THROW 5000\d", self.code)
        user = re.search(r"IF EXISTS \(SELECT 1 FROM msdb\.sys\.database_principals WHERE name = N'hc_reader'\)\s+THROW",
                         self.code)
        self.assertIsNotNone(login)
        self.assertIsNotNone(user)
        assert login is not None and user is not None
        self.assertLess(max(login.start(), user.start()), first_write)

    def test_create_login_is_unconditional(self):
        self.assertNotRegex(self.code, r"IS NULL\s+CREATE")
        self.assertIn("CREATE LOGIN hc_reader", self.code)

    def test_grants_unchanged(self):
        for g in ("GRANT VIEW SERVER STATE TO hc_reader", "GRANT VIEW ANY DEFINITION TO hc_reader",
                  "GRANT CONNECT ANY DATABASE TO hc_reader", "GRANT SELECT ON dbo.backupset TO hc_reader"):
            self.assertIn(g, self.code)
        self.assertEqual(self.code.count("GRANT "), 4)

    def test_no_sp_executesql_for_bin2_servers(self):
        # AZ-1407: SQL Server 2022 (Linux, CU28) with server collation Latin1_General_100_BIN2
        # fails every sp_executesql call with Msg 17750; EXEC (N'...') works there.
        self.assertNotIn("sp_executesql", self.code.lower())
        self.assertIn("EXEC (N'USE msdb; CREATE USER hc_reader FOR LOGIN hc_reader;", self.code)
        seed = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "lab", "seed-demo.sql")
        with open(seed, encoding="utf-8") as f:
            seed_code = "\n".join(l.split("--", 1)[0] for l in f.read().splitlines())
        self.assertNotIn("sp_executesql", seed_code.lower())


class CaseSensitiveCollationTests(unittest.TestCase):
    """AZ-1407: buyers run on CS/BIN2 servers (Latin1_General_CS_AS, *_BIN2).
    There, catalog names and identifiers resolve case-sensitively, and string
    comparisons follow the column collation. Offline proof only; lab run pending."""
    QUOTED = re.compile(r"N?'(?:[^']|'')*'")

    def _queries(self):
        return [(c["id"], c["sql"]) for c in ALL]

    def test_catalog_object_names_are_lowercase(self):
        for cid, sql in self._queries():
            body = self.QUOTED.sub("''", sql)
            for name in re.findall(r"\bsys\.(\w+)", body):
                self.assertEqual(name, name.lower(), f"{cid}: sys.{name}")

    def test_column_and_alias_spelling_is_consistent(self):
        # One spelling per identifier inside each query (s.User_Seeks vs s.user_seeks breaks on CS).
        for cid, sql in self._queries():
            body = self.QUOTED.sub("''", sql)
            seen = {}
            for tok in re.findall(r"\.(\w+)", body):
                seen.setdefault(tok.lower(), set()).add(tok)
            mixed = {k: v for k, v in seen.items() if len(v) > 1}
            self.assertFalse(mixed, f"{cid}: {mixed}")

    def test_sysadmin_service_sid_filter_ignores_case(self):
        # Setup creates 'NT Service\MSSQLSERVER' (mixed case) next to 'NT SERVICE\SQLWriter'.
        # On a CS server a plain NOT LIKE 'NT SERVICE\%' lists the engine's own service SID as a
        # finding; the filter must compare case-insensitively whatever the server collation.
        s08 = next(c for c in SERVER_CHECKS if c["id"] == "S08")
        guard(s08["sql"])
        self.assertIn("m.name COLLATE Latin1_General_CI_AS NOT LIKE 'NT SERVICE\\%'", s08["sql"])


if __name__ == "__main__":
    unittest.main()
