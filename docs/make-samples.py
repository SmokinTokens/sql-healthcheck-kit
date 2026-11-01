"""Rebuild docs/sample.md and docs/sample.html from docs/sample-results.json.

sample-results.json is synthetic: the DemoShop demo database (lab/seed-demo.sql)
in a throwaway container, with CPU, RAM and run time replaced by placeholders.
Run from the repo root: python3 docs/make-samples.py
"""
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from sqlhc.html_report import render_html  # noqa: E402
from sqlhc.runner import render_markdown  # noqa: E402

TITLE = "SQL Server Health Check (sample, demo data)"


def build():
    with open(os.path.join(ROOT, "docs", "sample-results.json"), encoding="utf-8") as f:
        data = json.load(f)
    md, _, _ = render_markdown(data, TITLE)
    page, _, _ = render_html(data, TITLE)
    return md, page


if __name__ == "__main__":
    md, page = build()
    for name, text in (("sample.md", md), ("sample.html", page)):
        with open(os.path.join(ROOT, "docs", name), "w", encoding="utf-8") as f:
            f.write(text)
        print("wrote docs/" + name)
