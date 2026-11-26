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

with open(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "README.md"),
          encoding="utf-8") as _f:
    README = _f.read()

ALL = SERVER_CHECKS + DB_CHECKS + [PRIV_PROBE, DB_PRIV_PROBE]


class AdviceSafetyTests(unittest.TestCase):
    def test_log_backup_advice_requires_strategy_and_reuse_wait_review(self):
        fix = next(c for c in SERVER_CHECKS if c["id"] == "S03")["fix"]
        for phrase in ("may grow", "D10", "log_reuse_wait_desc", "backup strategy",
                       "owner", "log-backup chain"):
            self.assertIn(phrase, fix)
        self.assertNotIn("keeps growing", fix)
        self.assertNotIn("switch to SIMPLE", fix)

    def test_index_removal_advice_preserves_integrity_and_named_dependencies(self):
        for cid in ("D02", "D03", "D05"):
            fix = next(c for c in DB_CHECKS if c["id"] == cid)["fix"]
            with self.subTest(check=cid):
                for phrase in ("Never drop unique indexes", "PRIMARY KEY", "UNIQUE constraints",
                               "full definitions", "INCLUDE", "filters", "index hints", "owner"):
                    self.assertIn(phrase, fix)
        fix = next(c for c in DB_CHECKS if c["id"] == "D05")["fix"]
        self.assertIn("full business cycle", fix)
        self.assertIn("month-end", fix)
        self.assertIn("do not prove an index is unnecessary", fix)
        self.assertIn("resets", fix)
        d01 = next(c for c in DB_CHECKS if c["id"] == "D01")["fix"]
        for phrase in ("table owner", "intentional", "maintenance window", "blocks access"):
            self.assertIn(phrase, d01)

    def test_suspect_page_advice_distinguishes_record_from_read_error_proof(self):
        check = next(c for c in SERVER_CHECKS if c["id"] == "S22")
        for text in (check["fix"], IMPACT["S22"]):
            self.assertIn("recorded suspect_pages entry", text)
            self.assertIn("not proof of a read-error event", text)
            self.assertIn("DBCC CHECKDB", text)
        self.assertNotIn("has logged read errors", IMPACT["S22"])


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
        self.assertEqual(len(IMPACT), 32)
        for cid, text in IMPACT.items():
            self.assertTrue(text.endswith("."), cid)
            self.assertNotIn("\n", text, cid)
            self.assertEqual(text.count(". "), 0, cid)    # one sentence
            self.assertLessEqual(len(text), 220, cid)
        for c in SERVER_CHECKS + DB_CHECKS:
            self.assertIn(c["area"], AREA_RANK, c["id"])

    def test_area_rank_order(self):
        order = sorted(AREA_RANK, key=lambda a: AREA_RANK[a])
        self.assertEqual(order[:5], ["Recoverability", "Integrity", "Security", "Configuration", "Performance"])

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
        self.assertNotIn("Nothing in this run needs action", md)
        self.assertIn("assessment is INCOMPLETE", md)
        self.assertIn("1 check(s) could not run, so this summary may miss risks", md)

    def test_exec_summary_skipped_dbs_is_not_clean(self):
        data = self.fake()
        for cid in ("S04", "S10"):
            data["results"]["server"][cid] = {"rows": []}
        data["results"]["db"]["Shop"]["D01"] = {"rows": []}
        data["skipped_dbs"] = ["we\nird"]
        md, _, errors = render_markdown(data)
        self.assertEqual(errors, [])
        self.assertNotIn("Nothing in this run needs action", md)
        self.assertIn("assessment is INCOMPLETE", md)
        self.assertIn("1 database(s) were skipped and not checked", md)

    def test_exec_summary_backup_texts_do_not_quantify_loss(self):
        for cid in ("S02", "S03"):
            self.assertIn("For the listed databases", IMPACT[cid])
            self.assertNotIn("week or more", IMPACT[cid])

    def test_exec_summary_clean_run(self):
        data = self.fake()
        for cid in ("S04", "S10"):
            data["results"]["server"][cid] = {"rows": []}
        data["results"]["db"]["Shop"]["D01"] = {"rows": []}
        md, _, errors = render_markdown(data)
        self.assertEqual(errors, [])
        self.assertIn("No findings. Nothing in this run needs action", md)
        self.assertNotIn("INCOMPLETE", md)
        self.assertNotIn("could not run", md)

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


class CorruptionCheckTests(unittest.TestCase):
    """S22 suspect pages + S23 last good CHECKDB. Offline proof only."""
    S22 = next(c for c in SERVER_CHECKS if c["id"] == "S22")
    S23 = next(c for c in SERVER_CHECKS if c["id"] == "S23")

    def test_shape_and_guard(self):
        for c, n, sev in ((self.S22, 6, "high"), (self.S23, 2, "medium")):
            guard(c["sql"])
            self.assertEqual(c["severity"], sev)
            self.assertEqual(c["area"], "Integrity")
            self.assertTrue(c["fix"])
            self.assertEqual(len(c["cols"]), n)

    def test_s22_reads_only_suspect_pages_and_skips_resolved_rows(self):
        sql = self.S22["sql"]
        self.assertEqual(set(re.findall(r"\b(?:msdb\.dbo|sys)\.\w+", sql)), {"msdb.dbo.suspect_pages"})
        # 1 = 823/824, 2 = bad checksum, 3 = torn page; 4/5/7 = restored/repaired/deallocated.
        self.assertIn("WHERE sp.event_type IN (1, 2, 3)", sql)
        self.assertIn("TOP (20)", sql)
        # Dropped database: show its id, not NULL.
        self.assertIn("ISNULL(DB_NAME(sp.database_id), CAST(sp.database_id AS varchar(10)))", sql)

    def test_s23_flags_never_unknown_and_older_than_7_days(self):
        sql = self.S23["sql"]
        self.assertIn("DATABASEPROPERTYEX(d.name, 'LastGoodCheckDbTime')", sql)
        # 1900-01-01 means never run; NULL means the server cannot report it.
        self.assertIn("WHEN x.t IS NULL THEN 'UNKNOWN'", sql)
        self.assertIn("WHEN x.t < '19000102' THEN 'NEVER'", sql)
        self.assertIn("x.t IS NULL OR x.t < DATEADD(day, -7, GETDATE())", sql)
        # Online, not tempdb, not a database snapshot.
        self.assertIn("d.name <> 'tempdb' AND d.state = 0 AND d.source_database_id IS NULL", sql)

    def test_exact_case_identifiers_for_bin2_servers(self):
        # Catalog names resolve case-sensitively on CS/BIN2 servers.
        self.assertIn("msdb.dbo.suspect_pages", self.S22["sql"])
        for col in ("database_id", "file_id", "page_id", "event_type", "error_count", "last_update_date"):
            self.assertIn("sp." + col, self.S22["sql"])
        self.assertIn("'LastGoodCheckDbTime'", self.S23["sql"])
        self.assertIn("source_database_id", self.S23["sql"])

    def test_cites_microsoft_learn(self):
        path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "sqlhc", "checks.py")
        with open(path, encoding="utf-8") as f:
            src = f.read()
        self.assertIn("learn.microsoft.com/sql/relational-databases/system-tables/suspect-pages-transact-sql", src)
        self.assertIn("learn.microsoft.com/sql/t-sql/functions/databasepropertyex-transact-sql", src)

    def test_output_parses(self):
        out = ("DemoShop\x1f1\x1f312\x1fbad checksum\x1f3\x1f2026-11-20 03:14:00\n\n(1 rows affected)\n")
        d = [0]
        self.assertEqual(rows_of(out, len(self.S22["cols"]), d),
                         [["DemoShop", "1", "312", "bad checksum", "3", "2026-11-20 03:14:00"]])
        out = "master\x1fNEVER\nDemoShop\x1f2026-11-01 02:00:00\n\n(2 rows affected)\n"
        self.assertEqual(rows_of(out, len(self.S23["cols"]), d)[0], ["master", "NEVER"])
        self.assertEqual(d[0], 0)

    def test_findings_render_and_count(self):
        server = {c["id"]: {"rows": []} for c in SERVER_CHECKS}
        server["S01"] = {"rows": [["16.0.1", "RTM", "Developer", "4", "8000", "300"]]}
        server["S22"] = {"rows": [["DemoShop", "1", "312", "bad checksum", "3", "2026-11-20 03:14:00"]]}
        server["S23"] = {"rows": [["master", "NEVER"], ["DemoShop", "UNKNOWN"]]}
        data = {"started": "2026-01-01T00:00:00", "secs": 1.0, "probe": {}, "powerful": [],
                "dbs": [], "skipped_dbs": [], "results": {"server": server, "db": {}},
                "full_query_text": False}
        self.assertEqual([f[0]["id"] for f in findings_of(data)], ["S22", "S23"])
        md, counts, _ = render_markdown(data)
        self.assertEqual(counts, {"high": 1, "medium": 1, "low": 0})
        self.assertIn("S22 [HIGH] Suspect pages", md)
        self.assertIn("S23 [MEDIUM] DBCC CHECKDB overdue or unverifiable", md)

    def test_compare_keys(self):
        from sqlhc.compare import CAPPED, KEY_COLS
        self.assertEqual(KEY_COLS["S22"], ["database", "file_id", "page_id"])
        self.assertEqual(KEY_COLS["S23"], ["database"])
        self.assertEqual(CAPPED["S22"], 20)
        for cid in ("S22", "S23"):
            chk = next(c for c in SERVER_CHECKS if c["id"] == cid)
            self.assertTrue(set(KEY_COLS[cid]) <= set(chk["cols"]))


class AgentJobTests(unittest.TestCase):
    """S24/S25: SQL Agent jobs from msdb, column-level SELECT only.
    The reader gets no SQLAgentReaderRole: its members are also SQLAgentUserRole
    (which P02 refuses) and can create and run their own jobs."""
    S24 = next(c for c in SERVER_CHECKS if c["id"] == "S24")
    S25 = next(c for c in SERVER_CHECKS if c["id"] == "S25")
    GRANTED = {
        "sysjobs": {"job_id", "name", "enabled"},
        "sysjobhistory": {"instance_id", "job_id", "step_id", "run_status", "run_date", "run_time"},
        "sysjobschedules": {"job_id", "schedule_id"},
        "sysschedules": {"schedule_id", "enabled"},
    }
    ALIAS = {"h": "sysjobhistory", "j": "sysjobs", "js": "sysjobschedules", "s": "sysschedules"}

    def setUp(self):
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        with open(os.path.join(root, "sql", "grant-reader.sql"), encoding="utf-8") as f:
            self.grant = "\n".join(line.split("--", 1)[0] for line in f.read().splitlines())

    def test_shape_and_guard(self):
        for c, sev, n in ((self.S24, "medium", 4), (self.S25, "low", 1)):
            guard(c["sql"])
            self.assertEqual(c["severity"], sev)
            self.assertTrue(c["fix"])
            self.assertEqual(len(c["cols"]), n)

    def test_last_failed_timestamp_is_run_start(self):
        self.assertEqual(self.S24["cols"][-1], "last_failed_run_start")

    def test_reads_only_the_four_agent_tables(self):
        for c in (self.S24, self.S25):
            objs = set(re.findall(r"\bmsdb\.dbo\.(\w+)", c["sql"]))
            self.assertTrue(objs <= set(self.GRANTED), (c["id"], objs))
            self.assertNotRegex(c["sql"], r"\bsys\.")

    def test_every_column_is_granted(self):
        # Column-level SELECT: any other column (owner_sid, message, ...) fails with Msg 230.
        for c in (self.S24, self.S25):
            for alias, col in re.findall(r"\b(h|j|js|s)\.(\w+)", c["sql"]):
                self.assertIn(col, self.GRANTED[self.ALIAS[alias]], f"{c['id']}: {alias}.{col}")
            for bad in ("message", "owner_sid", "step_name", "server", "command"):
                self.assertNotRegex(c["sql"], rf"\b{bad}\b", f"{c['id']} reads {bad}")

    def test_no_star_reads(self):
        for c in (self.S24, self.S25):
            self.assertNotRegex(c["sql"], r"SELECT\s+\*|COUNT\(\s*\*\s*\)|\w\.\*")

    def test_s24_counts_failed_job_outcomes_in_7_days(self):
        sql = self.S24["sql"]
        self.assertIn("h.step_id = 0 AND h.run_status = 0", sql)
        self.assertIn("DATEADD(day, -7, GETDATE())", sql)
        self.assertIn("TOP (20)", sql)

    def test_s25_needs_an_enabled_schedule(self):
        sql = self.S25["sql"]
        self.assertIn("j.enabled = 1 AND NOT EXISTS", sql)
        self.assertIn("s.enabled = 1", sql)

    def test_grant_script_matches_columns_read(self):
        for table, cols in self.GRANTED.items():
            m = re.search(rf"GRANT SELECT \(([^)]*)\) ON dbo\.{table} TO hc_reader", self.grant)
            self.assertIsNotNone(m, table)
            assert m is not None
            self.assertEqual({x.strip() for x in m.group(1).split(",")}, cols, table)
        for role in ("SQLAgentReaderRole", "SQLAgentUserRole", "SQLAgentOperatorRole", "sp_addrolemember",
                     "ALTER ROLE"):
            self.assertNotIn(role.lower(), self.grant.lower())

    def test_p02_does_not_count_select_grants_as_write(self):
        # The new grants are SELECT (type 'SL'); P02 flags only write/exec/alter types.
        self.assertIn("p.type IN ('IN', 'UP', 'DL', 'EX', 'AL', 'CL', 'TO', 'IM')", DB_PRIV_PROBE["sql"])
        self.assertNotIn("'SL'", DB_PRIV_PROBE["sql"])

    def test_lab_shaped_output_parses_and_renders(self):
        out = "nightly-etl\x1fenabled\x1f3\x1f2026-11-23 02:00:00\n\n(1 rows affected)\n"
        d = [0]
        rows = rows_of(out, len(self.S24["cols"]), d)
        self.assertEqual(d[0], 0)
        self.assertEqual(rows, [["nightly-etl", "enabled", "3", "2026-11-23 02:00:00"]])
        server = {c["id"]: {"rows": []} for c in SERVER_CHECKS}
        server["S01"] = {"rows": [["16.0.1", "RTM", "Developer", "4", "8000", "300"]]}
        server["S24"] = {"rows": rows}
        server["S25"] = {"rows": [["orphan job"]]}
        data = {"started": "2026-01-01T00:00:00", "secs": 1.0, "probe": {}, "powerful": [],
                "dbs": [], "skipped_dbs": [], "results": {"server": server, "db": {}},
                "full_query_text": False}
        self.assertEqual([f[0]["id"] for f in findings_of(data)], ["S24", "S25"])
        md, counts, _ = render_markdown(data)
        self.assertEqual(counts, {"high": 0, "medium": 1, "low": 1})
        self.assertIn("S24 [MEDIUM] SQL Agent jobs that failed", md)
        self.assertIn("nightly\\-etl", md)  # Markdown-escaped job name

    def test_compare_keys_by_job_and_caps(self):
        from sqlhc.compare import CAPPED, KEY_COLS
        self.assertEqual(KEY_COLS["S24"], ["job"])
        self.assertEqual(KEY_COLS["S25"], ["job"])
        self.assertEqual(CAPPED["S24"], 20)
        self.assertEqual(CAPPED["S25"], 50)

    def test_s24_window_is_rolling_to_the_second(self):
        # Review r1: a yyyyMMdd-only cutoff kept a failure from 7 days ago at 00:00 when the
        # check ran at 15:00. The packed date+time term must compare against the full cutoff.
        sql = self.S24["sql"]
        self.assertIn("CAST(h.run_date AS bigint) * 1000000 + h.run_time >=", sql)
        for part in ("hour", "minute", "second"):
            self.assertIn(f"DATEPART({part}, DATEADD(day, -7, GETDATE()))", sql)

        # Pure-Python mirror of the same packing (offline proof of the arithmetic only;
        # the SQL itself still needs the lab run).
        import datetime as dt

        def packed(t):
            return int(t.strftime("%Y%m%d")) * 1000000 + t.hour * 10000 + t.minute * 100 + t.second
        now = dt.datetime(2026, 11, 24, 15, 0, 0)
        cut = packed(now - dt.timedelta(days=7))
        self.assertLess(packed(dt.datetime(2026, 11, 17, 0, 0, 0)), cut)
        self.assertLess(packed(dt.datetime(2026, 11, 17, 14, 59, 59)), cut)
        self.assertGreaterEqual(packed(dt.datetime(2026, 11, 17, 15, 0, 0)), cut)
        self.assertGreaterEqual(packed(dt.datetime(2026, 11, 18, 0, 0, 0)), cut)

    def test_compare_never_calls_a_vanished_s24_row_fixed(self):
        from sqlhc.compare import compare

        def run(s24, s25):
            server = {c["id"]: {"rows": []} for c in SERVER_CHECKS}
            server["S24"] = {"rows": s24}
            server["S25"] = {"rows": s25}
            return {"started": "2026-01-01T00:00:00", "secs": 1.0, "probe": {}, "powerful": [],
                    "dbs": [], "skipped_dbs": [], "results": {"server": server, "db": {}},
                    "full_query_text": False}
        before = run([["nightly-etl", "enabled", "3", "2026-11-23 02:00:00"]], [["orphan"]])
        after = run([], [])
        items = {x["check"]: x for x in compare(before, after)["items"]}
        self.assertEqual(items["S24"]["status"], "unknown")
        self.assertIn("7-day window", items["S24"]["reason"])
        self.assertEqual(items["S25"]["status"], "fixed")


class BackupQualityTests(unittest.TestCase):
    """S26/S27: quality of the latest full backup from msdb.dbo.backupset. Offline proof only;
    lab/assert-backup-quality.py is the lab gate for the real SQL."""
    S26 = next(c for c in SERVER_CHECKS if c["id"] == "S26")
    S27 = next(c for c in SERVER_CHECKS if c["id"] == "S27")

    def test_shape_and_guard(self):
        for c, sev, area, n in ((self.S26, "medium", "Recoverability", 3), (self.S27, "low", "Security", 2)):
            guard(c["sql"])
            self.assertEqual(c["severity"], sev)
            self.assertEqual(c["area"], area)
            self.assertTrue(c["fix"])
            self.assertEqual(len(c["cols"]), n)
            self.assertEqual(c["cols"][0], "database")

    def test_sit_next_to_s02_s03(self):
        ids = [c["id"] for c in SERVER_CHECKS]
        self.assertEqual(ids[ids.index("S03") + 1:ids.index("S03") + 3], ["S26", "S27"])

    def test_read_only_backupset_and_catalog(self):
        for c in (self.S26, self.S27):
            self.assertEqual(set(re.findall(r"\bmsdb\.dbo\.(\w+)", c["sql"])), {"backupset"})
            self.assertEqual(set(re.findall(r"\bsys\.(\w+)", c["sql"])), {"databases", "database_recovery_status"})
            self.assertNotRegex(c["sql"], r"SELECT\s+\*")

    def test_history_bound_to_current_database_incarnation(self):
        # Review r1: name-only matching let a dropped/recreated namesake's old backups count.
        for c in (self.S26, self.S27):
            self.assertIn("rs.database_id = d.database_id AND rs.database_guid IS NOT NULL", c["sql"])
            self.assertIn("b.database_guid = rs.database_guid", c["sql"])
        self.assertIn("b2.database_guid = rs.database_guid", self.S26["sql"])
        self.assertIn("CROSS APPLY", self.S27["sql"])  # S27: no current-copy full -> no row

    def test_s26_reports_recreated_db_whose_fulls_all_belong_to_an_older_copy(self):
        # Review r2: S02 matches by name, so an old copy's recent full hides a recreated database
        # with no full of its own. S26 must list it (name match, other or NULL GUID, no current full).
        sql = self.S26["sql"]
        self.assertIn("b3.database_guid IS NOT NULL AND b3.database_guid <> rs.database_guid", sql)
        self.assertIn("OR (f.backup_set_id IS NULL AND (o.backup_set_id IS NOT NULL OR n.backup_set_id IS NOT NULL))", sql)
        self.assertIn("WHEN f.backup_set_id IS NULL THEN 'no full since recreated or restored; '", sql)
        self.assertIn("CASE WHEN n.backup_set_id IS NULL THEN 'NONE FOR THIS COPY' ELSE 'UNKNOWN' END", sql)
        # No full of any copy: f, o and n all NULL -> no row (S02 lists it as NEVER).
        self.assertNotIn("CROSS APPLY", sql)
        self.assertIn("No full since recreated or restored", self.S26["fix"].replace("'", ""))

    def test_s26_null_guid_is_unknown_history_not_an_older_copy(self):
        # Lead adversarial LOW3: a NULL backupset.database_guid is unknown provenance.
        sql = self.S26["sql"]
        self.assertIn("b4.database_guid IS NULL) n", sql)
        self.assertNotIn("b3.database_guid IS NULL OR", sql)
        # Review r1 (this pass): NULL-GUID history wins over older-copy history, even when mixed,
        # so 'no full since recreated' (every full is older) is said only when no NULL GUID exists.
        unknown = ("CASE WHEN f.backup_set_id IS NULL AND n.backup_set_id IS NOT NULL\n"
                   "   THEN 'some fulls on record have no database_guid (history unknown); '")
        self.assertIn(unknown, sql)
        self.assertLess(sql.index(unknown), sql.index("'no full since recreated or restored; '"))
        fix = self.S26["fix"]
        self.assertIn("'History unknown' means no full matches the current copy and some fulls on record "
                      "have no database_guid", fix)
        self.assertIn("cannot tell which copy they belong to", fix)

    def test_s26_copy_only_advice_checks_strategy_before_adding_a_full(self):
        # Lead adversarial MED2: never tell a DBA to just add a regular full.
        fix = self.S26["fix"]
        self.assertNotIn("add a regular full", fix)
        a = fix.index("first check the real backup strategy with its owner")
        b = fix.index("A new regular full resets the differential base")
        self.assertLess(a, b)
        self.assertIn("do not add one without that check", fix)

    def test_s26_checksum_text_does_not_overclaim(self):
        # Lead adversarial LOW5: CONTINUE_AFTER_ERROR lets a checksum backup finish.
        fix = self.S26["fix"]
        self.assertNotIn("instead of being copied into it", fix)
        self.assertIn("CONTINUE_AFTER_ERROR", fix)
        self.assertIn("test a restore", fix)
        self.assertIn("CONTINUE_AFTER_ERROR", README)

    def test_latest_full_only_copy_only_included(self):
        for c in (self.S26, self.S27):
            self.assertIn("b.type = 'D'", c["sql"])
            # Review r1: equal datetime finish times need a deterministic winner.
            self.assertIn("ORDER BY b.backup_finish_date DESC, b.backup_set_id DESC", c["sql"])
            self.assertIn("SELECT TOP (1)", c["sql"])
            self.assertIn("d.state = 0", c["sql"])
            self.assertIn("d.name <> 'tempdb'", c["sql"])

    def test_s26_flags(self):
        sql = self.S26["sql"]
        self.assertIn("ISNULL(f.has_backup_checksums, 0) = 0", sql)
        self.assertIn("f.is_damaged = 1", sql)
        self.assertIn("b2.is_copy_only = 0", sql)
        self.assertIn("r.backup_set_id IS NULL", sql)
        for label in ("no CHECKSUM; ", "DAMAGED (taken despite errors); ", "copy-only fulls only; "):
            self.assertIn(label, sql)

    def test_s27_uses_backup_bound_evidence_only(self):
        # Lead adversarial MED1: current TDE state must not judge a historical backup.
        sql = self.S27["sql"]
        self.assertIn("f.encryptor_type IS NULL", sql)
        self.assertIn("UPPER(ISNULL(f.key_algorithm, N'NO_ENCRYPTION')) = N'NO_ENCRYPTION'", sql)
        self.assertNotIn("is_encrypted", sql)
        self.assertIn("NOT LIKE N'Express%'", sql)
        self.assertIn("NOT LIKE N'Web%'", sql)

    def test_s27_wording_native_encryption_not_recorded(self):
        # Lead adversarial LOW4: say what history shows, note other protection, verify first.
        from sqlhc.summary import IMPACT
        self.assertEqual(self.S27["title"], "Last full backup: native backup encryption not recorded")
        fix = self.S27["fix"]
        for phrase in ("records no native backup encryption", "backup history cannot show this",
                       "Verify how the backup files are protected before changing anything"):
            self.assertIn(phrase, fix)
        self.assertLess(fix.index("Verify how"), fix.index("WITH ENCRYPTION"))
        self.assertIn("no native encryption", IMPACT["S27"])
        self.assertIn("verify how they are protected before changing anything", IMPACT["S27"])
        self.assertNotIn("is not encrypted", IMPACT["S27"])
        self.assertIn("current TDE setting says\nnothing about an older backup", README)

    def test_lab_shaped_output_parses_and_renders(self):
        out = ("DemoShop\x1f2026-11-25 01:50:00\x1fno CHECKSUM; \n"
               "msdb\x1f2026-11-25 01:50:01\x1fcopy-only fulls only; \n\n(2 rows affected)\n")
        d = [0]
        rows = rows_of(out, len(self.S26["cols"]), d)
        self.assertEqual(d[0], 0)
        self.assertEqual([r[0] for r in rows], ["DemoShop", "msdb"])
        server = {c["id"]: {"rows": []} for c in SERVER_CHECKS}
        server["S01"] = {"rows": [["16.0.1", "RTM", "Developer", "4", "8000", "300"]]}
        server["S26"] = {"rows": rows}
        server["S27"] = {"rows": [["DemoShop", "2026-11-25 01:50:00"]]}
        data = {"started": "2026-01-01T00:00:00", "secs": 1.0, "probe": {}, "powerful": [],
                "dbs": [], "skipped_dbs": [], "results": {"server": server, "db": {}},
                "full_query_text": False}
        self.assertEqual([f[0]["id"] for f in findings_of(data)], ["S26", "S27"])
        md, counts, _ = render_markdown(data)
        self.assertEqual(counts, {"high": 0, "medium": 1, "low": 1})
        self.assertIn("S26 [MEDIUM] Last full backup without CHECKSUM", md)
        self.assertIn("S27 [LOW] Last full backup: native backup encryption not recorded", md)

    def test_compare_keys_by_database(self):
        from sqlhc.compare import CAPPED, KEY_COLS
        for cid in ("S26", "S27"):
            self.assertEqual(KEY_COLS[cid], ["database"])
            self.assertNotIn(cid, CAPPED)

    def test_compare_never_calls_a_vanished_backup_row_fixed(self):
        # Review r1: purging msdb history (or a restore: new database_guid) empties S26/S27.
        from sqlhc.compare import compare

        def run(s02, s26, s27):
            server = {c["id"]: {"rows": []} for c in SERVER_CHECKS}
            server["S02"] = {"rows": s02}
            server["S26"] = {"rows": s26}
            server["S27"] = {"rows": s27}
            return {"started": "2026-01-01T00:00:00", "secs": 1.0, "probe": {}, "powerful": [],
                    "dbs": ["DemoShop"], "skipped_dbs": [],
                    "results": {"server": server, "db": {"DemoShop": {c["id"]: {"rows": []} for c in DB_CHECKS}}},
                    "full_query_text": False}
        before = run([], [["DemoShop", "2026-11-20 01:00:00", "no CHECKSUM; "]],
                     [["DemoShop", "2026-11-20 01:00:00"], ["master", "2026-11-20 01:00:00"]])
        after = run([["DemoShop", "FULL", "NEVER"]], [], [])
        vanished = [x for x in compare(before, after)["items"] if x["check"] in ("S26", "S27")]
        self.assertEqual(len(vanished), 3)  # S26 DemoShop, S27 DemoShop, S27 master
        for x in vanished:
            self.assertEqual(x["status"], "unknown", x)
            self.assertIn("backup history may have been purged", x["reason"])

    def test_grant_covers_backupset(self):
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        with open(os.path.join(root, "sql", "grant-reader.sql"), encoding="utf-8") as f:
            self.assertIn("GRANT SELECT ON dbo.backupset TO hc_reader", f.read())


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
        # 4 base grants + 4 column-level msdb Agent grants (see AgentJobTests).
        self.assertEqual(self.code.count("GRANT "), 8)
        self.assertEqual(self.code.count("GRANT SELECT ("), 4)

    def test_no_sp_executesql_for_bin2_servers(self):
        # SQL Server 2022 (Linux, CU28) with server collation Latin1_General_100_BIN2
        # fails every sp_executesql call with Msg 17750; EXEC (N'...') works there.
        self.assertNotIn("sp_executesql", self.code.lower())
        self.assertIn("EXEC (N'USE msdb; CREATE USER hc_reader FOR LOGIN hc_reader;", self.code)
        seed = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "lab", "seed-demo.sql")
        with open(seed, encoding="utf-8") as f:
            seed_code = "\n".join(l.split("--", 1)[0] for l in f.read().splitlines())
        self.assertNotIn("sp_executesql", seed_code.lower())


class OrphanGuestTests(unittest.TestCase):
    """D07 orphaned users + D08 guest CONNECT. Offline proof; lab proof in lab/assert-security.py."""
    D07 = next(c for c in DB_CHECKS if c["id"] == "D07")
    D08 = next(c for c in DB_CHECKS if c["id"] == "D08")

    def test_shape_and_guard(self):
        for c, sev, n in ((self.D07, "low", 2), (self.D08, "medium", 2)):
            guard(c["sql"])
            self.assertEqual(c["severity"], sev)
            self.assertEqual(c["area"], "Security")
            self.assertTrue(c["fix"])
            self.assertEqual(len(c["cols"]), n)
            self.assertIn(c["id"], IMPACT)
            # Per-database checks only: never in the server list.
            self.assertNotIn(c["id"], {s["id"] for s in SERVER_CHECKS})

    def test_d07_matches_microsoft_learn_orphan_query(self):
        sql = self.D07["sql"]
        self.assertEqual(set(re.findall(r"\bsys\.\w+", sql)), {"sys.database_principals", "sys.server_principals"})
        self.assertIn("LEFT JOIN sys.server_principals sp ON sp.sid = dp.sid", sql)
        self.assertIn("WHERE sp.sid IS NULL AND dp.authentication_type_desc = 'INSTANCE'", sql)
        self.assertIn("TOP (50)", sql)

    def test_d08_reads_database_level_connect_grants_for_guest_only(self):
        sql = self.D08["sql"]
        self.assertEqual(set(re.findall(r"\bsys\.\w+", sql)), {"sys.database_permissions", "sys.database_principals"})
        # class 0 = DATABASE, CO = CONNECT, G/W = granted (with or without grant option); DENY excluded.
        self.assertIn("p.class = 0 AND p.type = 'CO' AND p.state IN ('G', 'W')", sql)
        # guest is principal_id 2: no name compare, so a CS collation cannot miss it.
        self.assertIn("p.grantee_principal_id = 2", sql)
        self.assertNotIn("'guest'", sql)

    def test_lab_output_parses(self):
        d = [0]
        out = "legacy_orphan\x1fSQL_USER\n\n(1 rows affected)\n"
        self.assertEqual(rows_of(out, 2, d), [["legacy_orphan", "SQL_USER"]])
        self.assertEqual(d[0], 0)
        out = "guest\x1fGRANT\n\n(1 rows affected)\n"
        self.assertEqual(rows_of(out, 2, d), [["guest", "GRANT"]])

    def test_findings_render_per_database(self):
        server = {c["id"]: {"rows": []} for c in SERVER_CHECKS}
        server["S01"] = {"rows": [["16.0.1", "RTM", "Developer", "4", "8000", "300"]]}
        db = {c["id"]: {"rows": []} for c in DB_CHECKS}
        db["D07"] = {"rows": [["legacy_orphan", "SQL_USER"]]}
        db["D08"] = {"rows": [["guest", "GRANT"]]}
        data = {"started": "2026-01-01T00:00:00", "secs": 1.0, "probe": {}, "powerful": [],
                "dbs": ["Shop"], "skipped_dbs": [], "results": {"server": server, "db": {"Shop": db}},
                "full_query_text": False}
        self.assertEqual([(f[0]["id"], f[1]) for f in findings_of(data)], [("D08", "Shop"), ("D07", "Shop")])
        md, counts, _ = render_markdown(data)
        self.assertEqual(counts, {"high": 0, "medium": 1, "low": 1})
        self.assertIn("legacy\\_orphan", md)


class CaseSensitiveCollationTests(unittest.TestCase):
    """Buyers run on CS/BIN2 servers (Latin1_General_CS_AS, *_BIN2).
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


class TransactionLogCheckTests(unittest.TestCase):
    """D09 (VLF count) and D10 (log_reuse_wait_desc): shape only; the lab proves the SQL runs."""

    def chk(self, cid):
        return next(c for c in DB_CHECKS if c["id"] == cid)

    def test_d09_counts_vlfs_of_current_db_above_1000(self):
        d09 = self.chk("D09")
        guard(d09["sql"])
        sql = " ".join(d09["sql"].split())
        self.assertIn("FROM sys.dm_db_log_info(DB_ID())", sql)
        self.assertIn("HAVING COUNT(li.vlf_sequence_number) > 1000", sql)
        self.assertNotIn("COUNT(*)", sql)
        self.assertEqual(d09["cols"], ["vlf_count", "log_mb"])
        self.assertEqual(d09["severity"], "low")

    def test_d10_ignores_routine_waits_only(self):
        d10 = self.chk("D10")
        guard(d10["sql"])
        sql = " ".join(d10["sql"].split())
        self.assertIn("d.database_id = DB_ID()", sql)
        self.assertIn("NOT IN ('NOTHING', 'CHECKPOINT')", sql)
        self.assertEqual(d10["cols"], ["log_reuse_wait", "recovery_model"])
        self.assertEqual((d10["area"], d10["severity"]), ("Recoverability", "medium"))

    def test_new_checks_sit_after_d06(self):
        ids = [c["id"] for c in DB_CHECKS]
        self.assertEqual(ids[ids.index("D06") + 1:], ["D07", "D08", "D09", "D10", "D11"])

    def test_findings_and_summary_include_log_checks(self):
        data = ReportTests().fake()
        data["results"]["db"]["Shop"]["D09"] = {"rows": [["1203", "250.4"]]}
        data["results"]["db"]["Shop"]["D10"] = {"rows": [["LOG_BACKUP", "FULL"]]}
        ids = [f[0]["id"] for f in findings_of(data)]
        self.assertIn("D09", ids)
        self.assertIn("D10", ids)
        top = [f[0]["id"] for f in top_findings(findings_of(data))]
        self.assertEqual(top[0], "D10")    # Recoverability outranks Security and the rest
        md, counts, errors = render_markdown(data)
        self.assertEqual(errors, [])
        self.assertEqual(counts, {"high": 1, "medium": 2, "low": 2})
        self.assertIn(IMPACT["D10"], md)
        self.assertIn("1203", md)

    def test_compare_vlf_count_change_is_changed_not_fixed(self):
        from sqlhc.compare import compare
        before, after = ReportTests().fake(), ReportTests().fake()
        before["results"]["db"]["Shop"]["D09"] = {"rows": [["1203", "250.4"]]}
        after["results"]["db"]["Shop"]["D09"] = {"rows": [["1450", "300.0"]]}
        items = [x for x in compare(before, after)["items"] if x["check"] == "D09"]
        self.assertEqual([x["status"] for x in items], ["changed"])
        after["results"]["db"]["Shop"]["D09"] = {"rows": []}
        items = [x for x in compare(before, after)["items"] if x["check"] == "D09"]
        self.assertEqual([x["status"] for x in items], ["fixed"])


class QueryStoreCheckTests(unittest.TestCase):
    """D11 (sys.database_query_store_options): shape and advice only; the lab proves the SQL runs."""

    def chk(self):
        return next(c for c in DB_CHECKS if c["id"] == "D11")

    def test_d11_flags_off_readonly_error_and_mismatch(self):
        d11 = self.chk()
        guard(d11["sql"])
        sql = " ".join(d11["sql"].split())
        self.assertIn("FROM sys.database_query_store_options q", sql)
        self.assertIn("WHERE q.actual_state IN (0, 1, 3) OR q.desired_state <> q.actual_state", sql)
        self.assertNotIn("SELECT *", sql)
        self.assertEqual(d11["cols"], ["desired_state", "actual_state", "readonly_reason",
                                       "storage_mb", "max_storage_mb"])
        self.assertEqual((d11["area"], d11["severity"]), ("Configuration", "low"))

    def test_d11_fix_is_owner_led_and_never_clears_history(self):
        fix = self.chk()["fix"]
        self.assertTrue(fix.startswith("Agree any change with the database owner first."))
        for phrase in ("OPERATION_MODE = READ_WRITE", "readonly_reason", "65536", "MAX_STORAGE_SIZE_MB",
                       "check free disk first", "readonly_reason is a bitmap", "every bit that is set",
                       "65537 = 65536 + 1", "do not change them just to restart capture",
                       "does not clear any other bit", "only when no remaining bit is an expected state",
                       "ask before changing it", "sp_query_store_consistency_check",
                       "Do not run SET QUERY_STORE CLEAR or CLEAR ALL as routine cleanup",
                       "separate owner decision"):
            self.assertIn(phrase, fix)
        # The CLEAR warning comes after every action, and no sentence recommends CLEAR.
        self.assertLess(fix.index("sp_query_store_consistency_check"), fix.index("Do not run SET QUERY_STORE CLEAR"))
        self.assertEqual(fix.count("CLEAR"), 2)

    def test_findings_and_compare_for_d11(self):
        from sqlhc.compare import compare
        data = ReportTests().fake()
        data["results"]["db"]["Shop"]["D11"] = {"rows": [["READ_WRITE", "READ_ONLY", "65536", "1000", "1000"]]}
        self.assertIn("D11", [f[0]["id"] for f in findings_of(data)])
        md, counts, errors = render_markdown(data)
        self.assertEqual(errors, [])
        self.assertIn(IMPACT["D11"], md)
        self.assertIn("65536", md)
        before, after = ReportTests().fake(), ReportTests().fake()
        before["results"]["db"]["Shop"]["D11"] = {"rows": [["OFF", "OFF", "0", "0", "100"]]}
        after["results"]["db"]["Shop"]["D11"] = {"rows": [["READ_WRITE", "READ_ONLY", "65536", "100", "100"]]}
        items = [x for x in compare(before, after)["items"] if x["check"] == "D11"]
        self.assertEqual([x["status"] for x in items], ["changed"])
        after["results"]["db"]["Shop"]["D11"] = {"rows": []}
        items = [x for x in compare(before, after)["items"] if x["check"] == "D11"]
        self.assertEqual([x["status"] for x in items], ["fixed"])


if __name__ == "__main__":
    unittest.main()


class OrphanCheckSafetyTests(unittest.TestCase):
    """D07 skips built-in users and never advises dropping a user's schemas or objects."""

    def test_d07_skips_builtin_principals(self):
        chk = next(c for c in DB_CHECKS if c["id"] == "D07")
        self.assertIn("principal_id > 4", chk["sql"])

    def test_d07_fix_never_drops_objects(self):
        chk = next(c for c in DB_CHECKS if c["id"] == "D07")
        fix = chk["fix"].lower()
        self.assertNotIn("drop any schema", fix)
        self.assertIn("owns no schema", fix)
        self.assertIn("leave it in place", fix)
        for word in ("schema itself", "denies", "grant options", "restores them"):
            self.assertIn(word, fix)

class S26AdviceSafetyTests(unittest.TestCase):
    """Every S26 new-full recommendation goes through the backup owner first."""

    def test_s26_no_unconditional_new_full(self):
        chk = next(c for c in SERVER_CHECKS if c["id"] == "S26")
        fix = chk["fix"].lower()
        self.assertNotIn("take a new full backup now", fix)
        self.assertNotIn("take a clean full", fix)
        self.assertIn("before taking any new regular full", fix)
        self.assertIn("differential", fix)
