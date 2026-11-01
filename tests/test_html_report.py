"""Offline tests for the HTML report and the shipped samples."""
import json
import os
import re
import sys
import unittest
from html.parser import HTMLParser

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "tests"))

from sqlhc.html_report import h, render_html  # noqa: E402
import test_sqlhc  # noqa: E402  (module import: its tests are not collected twice)

EVIL = ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>", "\"><svg onload=alert(1)>",
        "javascript:alert(1)", "abc\u202edef", "line\nbreak", "' onmouseover='x"]


class Tags(HTMLParser):
    def __init__(self):
        super().__init__()
        self.tags, self.attrs = [], []

    def handle_starttag(self, tag, attrs):
        self.tags.append(tag)
        self.attrs += [(tag, k, v) for k, v in attrs]


def parse(page):
    p = Tags()
    p.feed(page)
    return p


class HtmlReportTests(unittest.TestCase):
    def fake(self):
        return test_sqlhc.ReportTests("test_report_has_caveats").fake()

    def test_counts_match_markdown(self):
        page, counts, errors = render_html(self.fake())
        self.assertEqual(counts, {"high": 1, "medium": 1, "low": 1})
        self.assertEqual(errors, [])
        self.assertIn('class="card high"', page)
        self.assertIn('class="sev low"', page)
        self.assertIn("AUTO_CLOSE is ON for Shop", page)

    def test_self_contained(self):
        page, _, _ = render_html(self.fake())
        p = parse(page)
        self.assertNotIn("script", p.tags)
        self.assertNotIn("link", p.tags)
        self.assertNotIn("img", p.tags)
        for tag, k, v in p.attrs:
            self.assertNotIn(k, ("src", "href", "action", "srcset"), (tag, k, v))
            self.assertFalse(k.startswith("on"), (tag, k))
        self.assertNotRegex(page, r"url\(|@import|https?:")
        self.assertIn("default-src 'none'", page)

    def test_server_text_is_inert(self):
        d = self.fake()
        name = EVIL[0]
        d["dbs"] = [name]
        d["results"]["db"] = {name: d["results"]["db"]["Shop"]}
        d["results"]["db"][name]["D01"] = {"rows": [[e, "1"] for e in EVIL]}
        page, _, _ = render_html(d)
        p = parse(page)
        self.assertEqual(set(p.tags) - {"html", "head", "meta", "title", "style", "body", "main", "h1", "ul",
                                        "li", "p", "h2", "div", "b", "table", "thead", "tr", "th", "tbody",
                                        "td", "span", "section", "h3", "footer"}, set())
        for tag, k, v in p.attrs:
            self.assertFalse(k.startswith("on"), (tag, k))
        self.assertNotIn("\u202e", page)
        self.assertIn("&lt;script&gt;", page)
        self.assertIn("line break", page)

    def test_h_escapes_quotes_and_controls(self):
        self.assertEqual(h("a\"b'c<d>&"), "a&quot;b&#x27;c&lt;d&gt;&amp;")
        self.assertEqual(h("x\ty\x00z"), "x y z")
        self.assertEqual(h("x\u2066y"), "x\ufffdy")
        self.assertEqual(h("a\x85b\x9bc"), "a b c")


class CliTests(unittest.TestCase):
    def test_main_writes_md_html_and_json(self):
        import tempfile
        from unittest import mock
        from sqlhc import runner
        data = test_sqlhc.ReportTests("test_report_has_caveats").fake()
        with tempfile.TemporaryDirectory() as out, \
                mock.patch.object(runner, "Sqlcmd"), mock.patch.object(runner, "collect", return_value=data), \
                mock.patch("sys.stdout"):
            rc = runner.main(["--server", "x", "--windows-auth", "--out", out])
            self.assertEqual(rc, 0)
            self.assertEqual(sorted(os.listdir(out)), ["report.html", "report.md", "results.json"])
            with open(os.path.join(out, "report.html"), encoding="utf-8") as f:
                self.assertTrue(f.read().startswith("<!DOCTYPE html>"))


class SampleTests(unittest.TestCase):
    """docs/sample.md and docs/sample.html must be what make-samples.py builds now."""

    def test_samples_are_current(self):
        sys.path.insert(0, os.path.join(ROOT, "docs"))
        import importlib
        mk = importlib.import_module("make-samples")
        md, page = mk.build()
        with open(os.path.join(ROOT, "docs", "sample.md"), encoding="utf-8") as f:
            self.assertEqual(f.read(), md)
        with open(os.path.join(ROOT, "docs", "sample.html"), encoding="utf-8") as f:
            self.assertEqual(f.read(), page)

    def test_sample_data_is_synthetic(self):
        with open(os.path.join(ROOT, "docs", "sample-results.json"), encoding="utf-8") as f:
            d = json.load(f)
        self.assertEqual(d["dbs"], ["DemoShop"])
        self.assertIn("Synthetic sample", d["_note"])
        text = json.dumps(d)
        self.assertIsNone(re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b(?<!16\.0\.4305\.5)", text))
        self.assertIsNone(re.search(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+\.[A-Za-z]", text))


if __name__ == "__main__":
    unittest.main()
