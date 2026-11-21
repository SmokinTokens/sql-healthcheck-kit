"""Offline tests for sqlhc.compare. Run: python3 -m unittest discover -s tests

The 'before' fixture is a real results.json from a DemoShop lab run (SQL Server
16.0.4305.5, lab/run-lab.sh). The 'after' run is derived from it by removing the
rows that two planted-defect fixes make disappear: dropping IX_Orders_Cust_Dup
(D02, and its D03 overlap row) and re-trusting FK_Orders_Customers (D04).
"""
import copy
import json
import os
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))

from sqlhc.compare import CompareError, compare, load, main, render_markdown  # noqa: E402
from sqlhc.runner import esc  # noqa: E402

BEFORE = os.path.join(HERE, "fixtures", "lab-demoshop-before.json")


def lab_before():
    return load(BEFORE, "before")


def lab_after():
    d = copy.deepcopy(lab_before())
    db = d["results"]["db"]["DemoShop"]
    db["D02"]["rows"] = []
    db["D03"]["rows"] = [r for r in db["D03"]["rows"] if "IX_Orders_Cust_Dup" not in r]
    db["D04"]["rows"] = []
    d["started"] = "2026-11-27T09:00:00"
    return d


def by(diff, status):
    return sorted((x["check"], x["scope"]) for x in diff["items"] if x["status"] == status)


class LabCompareTests(unittest.TestCase):
    def test_two_planted_fixes_show_as_fixed(self):
        diff = compare(lab_before(), lab_after())
        self.assertEqual(by(diff, "fixed"), [("D02", "DemoShop"), ("D03", "DemoShop"), ("D04", "DemoShop")])
        self.assertEqual(by(diff, "new"), [])
        self.assertEqual(by(diff, "unknown"), [])
        self.assertEqual(diff["counts"]["changed"], 0)
        # Every other finding row stays open and unchanged.
        # (The fixture predates check S21, so runner.findings_of cannot read it; count here.)
        from sqlhc.checks import DB_CHECKS, SERVER_CHECKS
        b = lab_before()["results"]
        finding_rows = sum(len(b["server"][c["id"]]["rows"]) for c in SERVER_CHECKS
                           if c["severity"] != "info" and c["id"] in b["server"])
        finding_rows += sum(len(b["db"]["DemoShop"][c["id"]]["rows"]) for c in DB_CHECKS if c["severity"] != "info")
        self.assertEqual(diff["counts"]["unchanged"], finding_rows - 3)
        self.assertNotIn("S21", {x["check"] for x in diff["items"]})

    def test_check_missing_from_one_run_is_unknown(self):
        after = lab_after()
        after["results"]["server"]["S21"] = {"rows": [["DemoShop", "DemoShop", "ROWS", "9", "25", "1", "1"]]}
        diff = compare(lab_before(), after)
        s21 = [x for x in diff["items"] if x["check"] == "S21"]
        self.assertEqual([x["status"] for x in s21], ["unknown"])
        self.assertIn("before: check not in this run", s21[0]["reason"])

    def test_same_run_twice_is_all_unchanged(self):
        diff = compare(lab_before(), lab_before())
        self.assertEqual(set(x["status"] for x in diff["items"]), {"unchanged"})

    def test_reverse_order_reports_new(self):
        diff = compare(lab_after(), lab_before())
        self.assertEqual(by(diff, "new"), [("D02", "DemoShop"), ("D03", "DemoShop"), ("D04", "DemoShop")])
        self.assertEqual(by(diff, "fixed"), [])

    def test_measurement_change_is_changed_not_new(self):
        after = lab_after()
        after["results"]["db"]["DemoShop"]["D01"]["rows"] = [["dbo.OrderLines", "450000"]]
        diff = compare(lab_before(), after)
        changed = [x for x in diff["items"] if x["status"] == "changed"]
        self.assertEqual([(x["check"], x["before"][1], x["after"][1]) for x in changed],
                         [("D01", "400000", "450000")])
        self.assertEqual(diff["open_by_severity"]["medium"],
                         sum(1 for x in diff["items"] if x["severity"] == "medium"
                             and x["status"] in ("unchanged", "changed", "new")))

    def test_info_checks_are_ignored(self):
        after = lab_after()
        after["results"]["server"]["S01"]["rows"][0][5] = "200"
        after["results"]["db"]["DemoShop"]["D06"]["rows"][0][2] = "999"
        ids = {x["check"] for x in compare(lab_before(), after)["items"]}
        self.assertFalse(ids & {"S01", "S12", "S14", "D06"})

    def test_error_in_after_is_unknown_never_fixed(self):
        after = lab_after()
        after["results"]["db"]["DemoShop"]["D01"] = {"error": "permission denied"}
        after["results"]["server"]["S08"] = {"rows": [], "error": "1 output line(s) could not be parsed"}
        diff = compare(lab_before(), after)
        unknown = {x["check"] for x in diff["items"] if x["status"] == "unknown"}
        self.assertEqual(unknown, {"D01", "S08"})
        fixed = {x["check"] for x in diff["items"] if x["status"] == "fixed"}
        self.assertNotIn("D01", fixed)
        self.assertNotIn("S08", fixed)

    def test_error_with_no_findings_still_listed(self):
        before, after = lab_before(), lab_after()
        after["results"]["server"]["S11"] = {"error": "timeout"}  # S11 had no rows before
        diff = compare(before, after)
        s11 = [x for x in diff["items"] if x["check"] == "S11"]
        self.assertEqual([x["status"] for x in s11], ["unknown"])
        self.assertIn("after: check error: timeout", s11[0]["reason"])

    def test_database_missing_from_after_is_unknown(self):
        after = lab_after()
        after["dbs"] = []
        after["results"]["db"] = {}
        diff = compare(lab_before(), after)
        db_items = [x for x in diff["items"] if x["scope"] == "DemoShop"]
        self.assertTrue(db_items)
        self.assertEqual({x["status"] for x in db_items}, {"unknown"})
        self.assertIn("Not checked in the after run: DemoShop", render_markdown(diff))

    def test_database_missing_from_before_is_unknown_not_new(self):
        # Sales may have been OFFLINE or not accessible in the first run: not proof of new.
        after = lab_after()
        after["dbs"].append("Sales")
        after["results"]["db"]["Sales"] = copy.deepcopy(after["results"]["db"]["DemoShop"])
        after["results"]["server"]["S03"]["rows"].append(["Sales", "NEVER"])
        diff = compare(lab_before(), after)
        self.assertEqual(by(diff, "new"), [])
        sales = [x for x in diff["items"] if x["scope"] == "Sales"
                 or (x["after"] and x["after"][0] == "Sales")]
        self.assertTrue(sales)
        self.assertEqual({x["status"] for x in sales}, {"unknown"})
        self.assertIn(("D01", "Sales"), by(diff, "unknown"))
        self.assertIn("Not checked in the before run: Sales", render_markdown(diff))

    def test_malformed_rows_make_check_unknown(self):
        for bad in ([], ["dbo.OrderLines"], ["dbo.OrderLines", "400000", "x"], [{"a": 1}, "400000"],
                    [None, "400000"], ["dbo.OrderLines", 400000]):
            after = lab_after()
            after["results"]["db"]["DemoShop"]["D01"]["rows"] = [bad]
            diff = compare(lab_before(), after)
            d01 = {x["status"] for x in diff["items"] if x["check"] == "D01"}
            self.assertEqual(d01, {"unknown"}, bad)

    def test_missing_database_server_rows_not_fixed(self):
        after = lab_after()
        after["dbs"] = []
        after["results"]["db"] = {}
        for cid in ("S03", "S04", "S05", "S06", "S13"):
            rows = after["results"]["server"][cid]["rows"]
            after["results"]["server"][cid]["rows"] = [r for r in rows if r[0] != "DemoShop"]
        diff = compare(lab_before(), after)
        demo = [x for x in diff["items"] if x["check"] in ("S03", "S04", "S05", "S06", "S13")
                and x["before"] and x["before"][0] == "DemoShop"]
        self.assertTrue(demo)
        self.assertEqual({x["status"] for x in demo}, {"unknown"})
        # System-database rows can still be judged: master's S06 row stays unchanged.
        self.assertIn(("S06", "unchanged"), {(x["check"], x["status"]) for x in diff["items"]
                                             if x["before"] and x["before"][0] == "master"})

    def test_dblist_error_blocks_fixed_for_database_rows(self):
        after = lab_after()
        after["results"]["server"]["DBLIST"] = {"error": "permission denied"}
        after["results"]["server"]["S03"]["rows"] = []
        diff = compare(lab_before(), after)
        s03 = [x for x in diff["items"] if x["check"] == "S03"]
        self.assertEqual([x["status"] for x in s03], ["unknown"])

    def test_dblist_error_before_never_makes_new(self):
        before, after = lab_before(), lab_after()
        before["dbs"], before["results"]["db"] = [], {}
        before["results"]["server"]["DBLIST"] = {"error": "permission denied"}
        for cid in ("S03", "S04", "S05", "S06", "S13"):
            rows = before["results"]["server"][cid]["rows"]
            before["results"]["server"][cid]["rows"] = [r for r in rows if r[0] != "DemoShop"]
        diff = compare(before, after)
        self.assertEqual(by(diff, "new"), [])
        demo = [x for x in diff["items"] if x["scope"] == "DemoShop"]
        self.assertTrue(demo)
        self.assertEqual({x["status"] for x in demo}, {"unknown"})
        gap = [x for x in diff["items"] if x["check"] == "DBLIST"]
        self.assertEqual([(x["status"], x["scope"]) for x in gap], [("unknown", "(instance)")])
        self.assertIn("before: database list could not be read: permission denied", gap[0]["reason"])
        self.assertIn("DBLIST User database list", render_markdown(diff))

    def test_dblist_error_after_emits_gap_item(self):
        before, after = lab_before(), lab_after()
        after["dbs"], after["results"]["db"] = [], {}
        after["results"]["server"]["DBLIST"] = {"error": "denied"}
        diff = compare(before, after)
        self.assertEqual(by(diff, "fixed"), [])
        gap = [x for x in diff["items"] if x["check"] == "DBLIST"]
        self.assertEqual(len(gap), 1)
        self.assertIn("after: database list could not be read: denied", gap[0]["reason"])
        demo = [x for x in diff["items"] if x["scope"] == "DemoShop"]
        self.assertTrue(demo)
        self.assertEqual({x["status"] for x in demo}, {"unknown"})

    def test_no_dblist_error_no_gap_item(self):
        self.assertNotIn("DBLIST", {x["check"] for x in compare(lab_before(), lab_after())["items"]})

    def test_model_msdb_vanished_row_is_unknown(self):
        # S02 filters state = 0: model/msdb leaving the list may mean OFFLINE, not backed up.
        before, after = lab_before(), lab_after()
        rows = [["master", "SIMPLE", "NEVER"], ["model", "FULL", "NEVER"], ["msdb", "SIMPLE", "NEVER"]]
        before["results"]["server"]["S02"]["rows"] = rows
        after["results"]["server"]["S02"]["rows"] = []
        st = {x["before"][0]: x["status"] for x in compare(before, after)["items"] if x["check"] == "S02"}
        self.assertEqual(st, {"master": "fixed", "model": "unknown", "msdb": "unknown"})
        r = [x["reason"] for x in compare(before, after)["items"]
             if x["check"] == "S02" and x["before"][0] == "model"][0]
        self.assertIn("no evidence that system database model was online", r)

    def test_model_msdb_appearing_row_is_unknown_not_new(self):
        # Reverse of the above: model/msdb absent before may only mean OFFLINE then.
        before, after = lab_before(), lab_after()
        before["results"]["server"]["S02"]["rows"] = []
        after["results"]["server"]["S02"]["rows"] = [
            ["master", "SIMPLE", "NEVER"], ["model", "FULL", "NEVER"], ["msdb", "SIMPLE", "NEVER"]]
        items = [x for x in compare(before, after)["items"] if x["check"] == "S02"]
        st = {x["after"][0]: x["status"] for x in items}
        self.assertEqual(st, {"master": "new", "model": "unknown", "msdb": "unknown"})
        self.assertIn("before: no evidence that system database msdb was online",
                      [x["reason"] for x in items if x["after"][0] == "msdb"][0])
        # A state-free check (S06 file list) can still report model as new.
        before["results"]["server"]["S06"]["rows"] = []
        after["results"]["server"]["S06"]["rows"] = [["model", "modeldev", "ROWS", "10%", "8"]]
        s06 = [x["status"] for x in compare(before, after)["items"] if x["check"] == "S06"]
        self.assertEqual(s06, ["new"])

    def test_user_db_in_neither_inventory_not_new(self):
        before, after = lab_before(), lab_after()
        for d in (before, after):
            d["dbs"], d["results"]["db"] = [], {}
        before["results"]["server"]["S03"]["rows"] = []
        s03 = [x for x in compare(before, after)["items"] if x["check"] == "S03"]
        self.assertTrue(s03)
        self.assertEqual({x["status"] for x in s03}, {"unknown"})

    def test_model_file_row_state_free_check_can_be_fixed(self):
        before, after = lab_before(), lab_after()
        row = ["model", "modeldev", "ROWS", "10%", "8"]
        before["results"]["server"]["S06"]["rows"] = [row]
        after["results"]["server"]["S06"]["rows"] = []
        st = [x["status"] for x in compare(before, after)["items"] if x["check"] == "S06"]
        self.assertEqual(st, ["fixed"])

    def test_capped_before_list_full_after_row_is_unknown(self):
        def s13(i):
            return ["DemoShop", f"[t{i}]", "[a]", "", "", str(100 + i)]
        before, after = lab_before(), lab_after()
        before["results"]["server"]["S13"]["rows"] = [s13(i) for i in range(10)]
        after["results"]["server"]["S13"]["rows"] = [s13(i) for i in range(1, 11)]
        st = {x["after"][1]: (x["status"], x.get("reason", "")) for x in compare(before, after)["items"]
              if x["check"] == "S13" and x["after"]}
        self.assertEqual(st["[t10]"][0], "unknown")
        self.assertIn("before: list is a full top 10", st["[t10]"][1])
        # Below the cap in the first run, a newcomer is really new.
        before["results"]["server"]["S13"]["rows"] = [s13(i) for i in range(9)]
        st = {x["after"][1]: x["status"] for x in compare(before, after)["items"]
              if x["check"] == "S13" and x["after"]}
        self.assertEqual(st["[t10]"], "new")

    def test_capped_s21_both_directions(self):
        def s21(i):
            return ["DemoShop", f"f{i}", "ROWS", "1000", "25", "1", "1"]
        before, after = lab_before(), lab_after()
        before["results"]["server"]["S21"] = {"rows": [s21(i) for i in range(15)]}
        after["results"]["server"]["S21"] = {"rows": [s21(i) for i in range(1, 16)]}
        items = [x for x in compare(before, after)["items"] if x["check"] == "S21"]
        st = {(x["before"] or x["after"])[1]: x["status"] for x in items}
        self.assertEqual((st["f0"], st["f15"]), ("unknown", "unknown"))
        self.assertEqual(sum(1 for x in items if x["status"] == "unchanged"), 14)

    def test_database_in_neither_inventory_not_fixed(self):
        # e.g. DemoShop offline or no access in both runs: S03 saw it before, not after.
        before, after = lab_before(), lab_after()
        for d in (before, after):
            d["dbs"], d["results"]["db"] = [], {}
        after["results"]["server"]["S03"]["rows"] = []
        s03 = [x["status"] for x in compare(before, after)["items"] if x["check"] == "S03"]
        self.assertEqual(s03, ["unknown"])

    def test_s21_counter_move_is_changed(self):
        row = ["DemoShop", "DemoShop", "ROWS", "1000", "25", "10", "30"]
        before, after = lab_before(), lab_after()
        before["results"]["server"]["S21"] = {"rows": [row]}
        after["results"]["server"]["S21"] = {"rows": [row[:3] + ["2000"] + row[4:]]}
        s21 = [x["status"] for x in compare(before, after)["items"] if x["check"] == "S21"]
        self.assertEqual(s21, ["changed"])

    def test_unknown_item_with_after_row_counts_as_open(self):
        # Full S21 list before, a new slow file after: unknown, but proven open after.
        def s21(i):
            return ["DemoShop", f"f{i}", "ROWS", "1000", "25", "1", "1"]
        before, after = lab_before(), lab_after()
        for d in (before, after):
            for c in ("S02", "S03", "S04", "S05", "S06", "S07", "S08", "S09", "S10", "S11", "S13"):
                if c in d["results"]["server"]:
                    d["results"]["server"][c]["rows"] = []
            for c in d["results"]["db"]["DemoShop"].values():
                c["rows"] = []
        before["results"]["server"]["S21"] = {"rows": [s21(i) for i in range(15)]}
        after["results"]["server"]["S21"] = {"rows": [s21(99)]}
        diff = compare(before, after)
        s21_items = [x for x in diff["items"] if x["check"] == "S21"]
        st = {(x["after"] or x["before"])[1]: x["status"] for x in s21_items}
        self.assertEqual(st.pop("f99"), "unknown")
        self.assertEqual(set(st.values()), {"fixed"})  # after list below cap: real fixes
        self.assertEqual(diff["open_by_severity"]["medium"], 1)
        self.assertIn("Still open after (finding rows seen in the after run): 0 high, 1 medium",
                      render_markdown(diff))
        # An unknown item seen only before (after side errored) is not counted open.
        after["results"]["server"]["S21"] = {"error": "denied"}
        self.assertEqual(compare(before, after)["open_by_severity"]["medium"], 0)

    def test_open_after_counts_rows_when_before_unreadable(self):
        # Before run unreadable (check error, db list error): every item is unknown,
        # but 'still open after' comes from the readable after run alone.
        before, after = lab_before(), lab_after()
        expect = compare(lab_after(), lab_after())["open_by_severity"]
        self.assertGreater(sum(expect.values()), 0)
        for c in before["results"]["server"]:
            before["results"]["server"][c] = {"error": "denied"}
        for db in before["dbs"]:
            for c in before["results"]["db"][db]:
                before["results"]["db"][db][c] = {"error": "denied"}
        diff = compare(before, after)
        self.assertEqual(diff["counts"]["fixed"] + diff["counts"]["new"], 0)
        self.assertEqual(diff["open_by_severity"], expect)
        md = render_markdown(diff)
        self.assertIn(f"Still open after (finding rows seen in the after run): {expect['high']} high, "
                      f"{expect['medium']} medium, {expect['low']} low.", md)
        # Same count for any before run: it is a property of the after run only.
        self.assertEqual(compare(lab_before(), after)["open_by_severity"], expect)

    def test_sa_rename_is_changed_not_fixed_plus_new(self):
        before, after = lab_before(), lab_after()
        before["results"]["server"]["S10"]["rows"] = [["sa"]]
        after["results"]["server"]["S10"]["rows"] = [["dba_root"]]
        s10 = [x["status"] for x in compare(before, after)["items"] if x["check"] == "S10"]
        self.assertEqual(s10, ["changed"])
        after["results"]["server"]["S10"]["rows"] = []
        s10 = [x["status"] for x in compare(before, after)["items"] if x["check"] == "S10"]
        self.assertEqual(s10, ["fixed"])

    def test_d02_pair_orientation_is_not_identity(self):
        before, after = lab_before(), lab_after()
        before["results"]["db"]["DemoShop"]["D02"]["rows"] = [["dbo.T", "IX_A", "IX_B", "2"]]
        after["results"]["db"]["DemoShop"]["D02"]["rows"] = [["dbo.T", "IX_B", "IX_A", "2"]]
        d02 = [x["status"] for x in compare(before, after)["items"] if x["check"] == "D02"]
        self.assertEqual(d02, ["unchanged"])
        # Reverse direction too.
        d02 = [x["status"] for x in compare(after, before)["items"] if x["check"] == "D02"]
        self.assertEqual(d02, ["unchanged"])
        # A different partner index is still a different finding.
        after["results"]["db"]["DemoShop"]["D02"]["rows"] = [["dbo.T", "IX_C", "IX_A", "2"]]
        d02 = sorted(x["status"] for x in compare(before, after)["items"] if x["check"] == "D02")
        self.assertEqual(d02, ["fixed", "new"])

    def test_capped_list_ranked_out_is_unknown(self):
        def s13(i):
            return ["DemoShop", f"[t{i}]", "[a]", "", "", str(100 + i)]
        before, after = lab_before(), lab_after()
        before["results"]["server"]["S13"]["rows"] = [s13(i) for i in range(10)]
        after["results"]["server"]["S13"]["rows"] = [s13(i) for i in range(1, 11)]
        st = {x["before"][1]: x["status"] for x in compare(before, after)["items"]
              if x["check"] == "S13" and x["before"]}
        self.assertEqual(st["[t0]"], "unknown")
        # Below the cap, absence is a real fix.
        after["results"]["server"]["S13"]["rows"] = [s13(i) for i in range(1, 10)]
        st = {x["before"][1]: x["status"] for x in compare(before, after)["items"]
              if x["check"] == "S13" and x["before"]}
        self.assertEqual(st["[t0]"], "fixed")

    def test_duplicate_key_rows_ignore_order(self):
        r1 = ["DemoShop", "[t]", "[a]", "", "", "100"]
        r2 = ["DemoShop", "[t]", "[a]", "", "", "200"]
        before, after = lab_before(), lab_after()
        before["results"]["server"]["S13"]["rows"] = [r1, r2]
        after["results"]["server"]["S13"]["rows"] = [r2, r1]
        self.assertEqual([x["status"] for x in compare(before, after)["items"] if x["check"] == "S13"],
                         ["unchanged", "unchanged"])
        after["results"]["server"]["S13"]["rows"] = [r2]
        self.assertEqual(sorted(x["status"] for x in compare(before, after)["items"] if x["check"] == "S13"),
                         ["fixed", "unchanged"])

    def test_skipped_db_is_unknown_coverage_item(self):
        # The collector skips odd names and unparsable rows: they must show as gaps.
        for side in ("before", "after", "both"):
            before, after = lab_before(), lab_after()
            if side in ("before", "both"):
                before["skipped_dbs"] = ["odd[name]", "(unparsable name)"]
            if side in ("after", "both"):
                after["skipped_dbs"] = ["odd[name]"]
            diff = compare(before, after)
            sk = [x for x in diff["items"] if x["check"] == "SKIPPED"]
            want = {"before": [("odd[name]", "before"), ("(unparsable name)", "before")],
                    "after": [("odd[name]", "after")],
                    "both": [("odd[name]", "before"), ("(unparsable name)", "before"), ("odd[name]", "after")]}
            self.assertEqual(sorted((x["scope"], x["reason"].split(":")[0]) for x in sk), sorted(want[side]), side)
            self.assertEqual({x["status"] for x in sk}, {"unknown"})
            self.assertEqual(diff["counts"]["unknown"], len(want[side]), side)
            # The three planted fixes are unaffected.
            self.assertEqual(diff["counts"]["fixed"], 3)
            md = render_markdown(diff)
            self.assertIn(esc("odd[name]"), md)
            self.assertIn("database skipped by the collector", md)
        # No skipped list (older runs) or an empty one: no coverage item.
        before = lab_before()
        before.pop("skipped_dbs", None)
        self.assertNotIn("SKIPPED", {x["check"] for x in compare(before, lab_after())["items"]})

    def test_markdown_escapes_server_text(self):
        after = lab_after()
        after["results"]["server"]["S08"]["rows"].append(["<img src=x>|evil", "SQL_LOGIN", "enabled"])
        md = render_markdown(compare(lab_before(), after))
        self.assertNotIn("<img", md)
        self.assertIn("&lt;img", md)
        self.assertIn("## New since the first run (1)", md)
        self.assertIn("## Fixed (3)", md)


class LoadTests(unittest.TestCase):
    def _write(self, text):
        fd, path = tempfile.mkstemp(suffix=".json")
        with os.fdopen(fd, "w") as f:
            f.write(text)
        self.addCleanup(os.remove, path)
        return path

    def test_rejects_non_results_json(self):
        for text in ("[]", "{}", '{"results": {"server": {}, "db": {}}}',
                     '{"results": {"server": {}, "db": {}}, "dbs": ["X"]}', "not json"):
            with self.assertRaises(CompareError, msg=text):
                load(self._write(text), "x")

    def test_rejects_non_finite_numbers(self):
        for c in ("NaN", "Infinity", "-Infinity"):
            with self.assertRaises(CompareError):
                load(self._write('{"dbs": [], "secs": %s, "results": {"server": {}, "db": {}}}' % c), "x")

    def test_rejects_malformed_dblist(self):
        for v in ("1", "null", "[]", '"x"', "{}", '{"error": 5}', '{"rows": []}'):
            text = '{"dbs": [], "results": {"server": {"DBLIST": %s}, "db": {}}}' % v
            with self.assertRaises(CompareError, msg=v):
                load(self._write(text), "x")
        ok = '{"dbs": [], "results": {"server": {"DBLIST": {"error": "denied"}}, "db": {}}}'
        load(self._write(ok), "x")

    def test_rejects_duplicate_keys(self):
        with self.assertRaises(CompareError):
            load(self._write('{"dbs": [], "dbs": [], "results": {"server": {}, "db": {}}}'), "x")

    def test_cli_writes_report_and_refuses_overwrite(self):
        after = self._write(json.dumps(lab_after()))
        out = tempfile.mkdtemp()
        self.assertEqual(main([BEFORE, after, "--out", out]), 0)
        with open(os.path.join(out, "compare.json")) as f:
            self.assertEqual(json.load(f)["counts"]["fixed"], 3)
        with open(os.path.join(out, "compare.md")) as f:
            self.assertIn("**3 fixed, 0 new", f.read())
        self.assertEqual(main([BEFORE, after, "--out", out]), 2)
        for n in ("compare.md", "compare.json"):
            os.remove(os.path.join(out, n))
        os.rmdir(out)

    def test_cli_refusal_leaves_no_partial_pair(self):
        after = self._write(json.dumps(lab_after()))
        out = tempfile.mkdtemp()
        jp, rp = os.path.join(out, "compare.json"), os.path.join(out, "compare.md")
        with open(jp, "w") as f:
            f.write("old")
        self.assertEqual(main([BEFORE, after, "--out", out]), 2)
        self.assertFalse(os.path.exists(rp))
        with open(jp) as f:
            self.assertEqual(f.read(), "old")
        os.remove(jp)
        os.rmdir(out)

    def test_cli_race_removes_own_partial_file(self):
        # compare.json appears after the pre-check: the new compare.md must not stay.
        import builtins
        from unittest import mock
        after = self._write(json.dumps(lab_after()))
        out = tempfile.mkdtemp()
        jp, rp = os.path.join(out, "compare.json"), os.path.join(out, "compare.md")
        real_open = builtins.open

        def racing_open(path, mode="r", *a, **k):
            if path == jp and mode == "x":
                with real_open(jp, "w") as f:
                    f.write("other")
            return real_open(path, mode, *a, **k)
        with mock.patch("builtins.open", racing_open):
            self.assertEqual(main([BEFORE, after, "--out", out]), 2)
        self.assertFalse(os.path.exists(rp))
        with open(jp) as f:
            self.assertEqual(f.read(), "other")
        os.remove(jp)
        os.rmdir(out)

    def test_cli_write_error_removes_own_partial_file(self):
        # A non-FileExists write error on compare.json (e.g. disk full) must not
        # leave the new compare.md behind.
        import builtins
        from unittest import mock
        after = self._write(json.dumps(lab_after()))
        out = tempfile.mkdtemp()
        jp, rp = os.path.join(out, "compare.json"), os.path.join(out, "compare.md")
        real_open = builtins.open

        def failing_open(path, mode="r", *a, **k):
            if path == jp and mode == "x":
                raise OSError(28, "No space left on device", jp)
            return real_open(path, mode, *a, **k)
        with mock.patch("builtins.open", failing_open):
            self.assertEqual(main([BEFORE, after, "--out", out]), 2)
        self.assertFalse(os.path.exists(rp))
        self.assertFalse(os.path.exists(jp))
        os.rmdir(out)

    def test_rejects_malformed_skipped_dbs(self):
        for v in ('"x"', "[1]", "{}", "null"):
            with self.assertRaises(CompareError, msg=v):
                load(self._write('{"dbs": [], "skipped_dbs": %s, "results": {"server": {}, "db": {}}}' % v), "x")

    def test_cli_unicode_under_ascii_locale(self):
        # LC_ALL=C with locale coercion and UTF-8 mode off: the default text encoding
        # is ASCII. A Unicode login must still write a full UTF-8 report pair.
        import subprocess
        after = lab_after()
        after["results"]["server"]["S08"]["rows"].append(["José_ü€", "SQL_LOGIN", "enabled"])
        ap = self._write(json.dumps(after))
        out = tempfile.mkdtemp()
        env = dict(os.environ, LC_ALL="C", LANG="C", PYTHONCOERCECLOCALE="0", PYTHONUTF8="0",
                   PYTHONIOENCODING="utf-8")
        root = os.path.dirname(HERE)
        enc = subprocess.run([sys.executable, "-X", "utf8=0", "-c", "import locale; print(locale.getpreferredencoding(False))"],
                             env=env, capture_output=True, text=True).stdout.strip()
        if "utf" in enc.lower().replace("-", ""):
            self.skipTest(f"cannot get a non-UTF-8 locale here ({enc})")
        r = subprocess.run([sys.executable, "-X", "utf8=0", "-m", "sqlhc.compare", BEFORE, ap, "--out", out],
                           env=env, cwd=root, capture_output=True, text=True, encoding="utf-8")
        self.assertEqual(r.returncode, 0, r.stderr)
        with open(os.path.join(out, "compare.md"), encoding="utf-8") as f:
            self.assertIn(esc("José_ü€"), f.read())
        with open(os.path.join(out, "compare.json"), encoding="utf-8") as f:
            self.assertEqual(json.load(f)["counts"]["new"], 1)
        for n in ("compare.md", "compare.json"):
            os.remove(os.path.join(out, n))
        os.rmdir(out)

    def test_cli_non_oserror_write_failure_removes_own_partial_file(self):
        # Any write failure (here UnicodeEncodeError on compare.json) goes through cleanup.
        import builtins
        from unittest import mock
        after = self._write(json.dumps(lab_after()))
        out = tempfile.mkdtemp()
        jp, rp = os.path.join(out, "compare.json"), os.path.join(out, "compare.md")
        real_open = builtins.open

        def failing_open(path, mode="r", *a, **k):
            if path == jp and mode == "x":
                raise UnicodeEncodeError("ascii", "\u20ac", 0, 1, "ordinal not in range(128)")
            return real_open(path, mode, *a, **k)
        with mock.patch("builtins.open", failing_open):
            self.assertEqual(main([BEFORE, after, "--out", out]), 2)
        self.assertFalse(os.path.exists(rp))
        self.assertFalse(os.path.exists(jp))
        os.rmdir(out)

    def test_cli_bad_input_exit_2(self):
        self.assertEqual(main([BEFORE, self._write("{}"), "--out", tempfile.gettempdir()]), 2)


if __name__ == "__main__":
    unittest.main()
