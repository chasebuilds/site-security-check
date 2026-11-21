"""Render a Report as JSON or as a plain-English HTML page (one file, no external assets)."""

from __future__ import annotations

import json
from html import escape

from .models import Finding, Report

_GROUPS = (
    ("fail", "Fix these first"),
    ("warn", "Worth improving"),
    ("pass", "Looking good"),
    ("info", "Good to know"),
    ("skipped", "Not checked"),
)
_LABEL = {"fail": "Fix", "warn": "Improve", "pass": "OK", "info": "Note", "skipped": "Skipped"}

_CSS = """
:root{--ink:#2a2019;--ink2:rgba(42,32,25,.68);--card:rgba(255,252,248,.62);--edge:rgba(255,255,255,.6);
--glass:rgba(255,250,244,.3);--shadow:rgba(70,40,20,.22);--good:#1f7a5a;--bad:#b23a22;--warn:#9a5d08;
--gbg:rgba(31,154,114,.15);--bbg:rgba(226,88,58,.15);--wbg:rgba(200,130,20,.16);--nbg:rgba(42,32,25,.08)}
@media(prefers-color-scheme:dark){:root{--ink:#f6ece2;--ink2:rgba(246,236,226,.72);--card:rgba(48,36,28,.6);
--edge:rgba(255,255,255,.14);--glass:rgba(34,24,18,.4);--shadow:rgba(0,0,0,.5);--good:#4fd1a1;--bad:#ff8a6a;
--warn:#f0b45a;--gbg:rgba(79,209,161,.16);--bbg:rgba(255,122,85,.18);--wbg:rgba(240,180,90,.17);
--nbg:rgba(246,236,226,.1)}}
*{box-sizing:border-box}
body{margin:0;min-height:100vh;color:var(--ink);font:15px/1.55 "Segoe UI",system-ui,sans-serif;
background:radial-gradient(60% 50% at 80% 8%,#fff3dc 0,transparent 70%),
linear-gradient(180deg,#e9ddcf,#cdb9a3 70%,#b89a80)}
@media(prefers-color-scheme:dark){body{background:radial-gradient(60% 50% at 80% 8%,#6b4420 0,transparent 70%),
linear-gradient(180deg,#3b2c22,#2a1f19 70%,#241a14)}}
main{max-width:860px;margin:0 auto;padding:20px 16px 60px}
.bar{display:inline-flex;gap:10px;align-items:center;padding:8px 16px;border-radius:999px;font-size:13px;
background:var(--glass);border:1px solid var(--edge);backdrop-filter:blur(22px) saturate(150%);
-webkit-backdrop-filter:blur(22px) saturate(150%);margin-bottom:16px}
.panel{background:var(--glass);border:1px solid var(--edge);border-radius:28px;padding:clamp(18px,3vw,30px);
backdrop-filter:blur(26px) saturate(150%);-webkit-backdrop-filter:blur(26px) saturate(150%);
box-shadow:0 24px 60px -20px var(--shadow)}
h1{margin:0 0 4px;font-size:clamp(22px,3.4vw,30px);letter-spacing:-.02em}
h2{margin:28px 0 10px;font-size:15px;text-transform:uppercase;letter-spacing:.06em;color:var(--ink2)}
.top{display:flex;gap:22px;align-items:center;flex-wrap:wrap}
.grade{width:92px;height:92px;border-radius:50%;display:grid;place-items:center;font-size:46px;font-weight:700;
background:var(--card);border:1px solid var(--edge)}
.g-A,.g-B{color:var(--good)}.g-C,.g-D{color:var(--warn)}.g-F{color:var(--bad)}
.muted{color:var(--ink2)}
.card{background:var(--card);border:1px solid var(--edge);border-radius:18px;padding:14px 16px;margin:0 0 10px}
.card h3{margin:0 0 4px;font-size:16px}
.pill{display:inline-block;font-size:11px;font-weight:700;padding:2px 10px;border-radius:999px;margin-right:8px;
vertical-align:2px}
.fail{background:var(--bbg);color:var(--bad)}.warn{background:var(--wbg);color:var(--warn)}
.pass{background:var(--gbg);color:var(--good)}.info,.skipped{background:var(--nbg);color:var(--ink2)}
.card p{margin:6px 0 0}.card b{font-weight:600}
.saw{font-family:ui-monospace,"Cascadia Mono",monospace;font-size:13px;overflow-wrap:anywhere}
footer{margin-top:22px;font-size:13px;color:var(--ink2)}
"""


def _card(f: Finding) -> str:
    detail = ""
    if f.status in {"fail", "warn"}:
        detail = (
            f"<p><b>What it means:</b> {escape(f.meaning)}</p>"
            f"<p><b>How to fix it:</b> {escape(f.fix)}</p>"
        )
    return (
        f'<div class="card"><h3><span class="pill {f.status}">{_LABEL[f.status]}</span>'
        f"{escape(f.title)}</h3>"
        f'<p class="saw">{escape(f.summary)}</p>{detail}</div>'
    )


def to_html(report: Report) -> str:
    counts = {s: sum(1 for f in report.findings if f.status == s) for s, _ in _GROUPS}
    sections = []
    for status, heading in _GROUPS:
        items = [f for f in report.findings if f.status == status]
        if items:
            sections.append(f"<h2>{heading} ({len(items)})</h2>" + "".join(_card(f) for f in items))
    notes = "".join(f"<p class='muted'>{escape(n)}</p>" for n in report.notes)
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Website security checkup: {escape(report.target)}</title>
<style>{_CSS}</style></head><body><main>
<div class="bar">Website security checkup &middot; {escape(report.scanned_at)}</div>
<div class="panel">
<div class="top"><div class="grade g-{report.grade}">{report.grade}</div>
<div><h1>{escape(report.target)}</h1>
<div class="muted">Score {report.score} out of 100. {counts["fail"]} to fix,
{counts["warn"]} to improve, {counts["pass"]} fine. {report.requests_made} requests made.</div></div></div>
{notes}{"".join(sections)}
<footer>This is a passive checkup: it reads what the site already shows to every visitor. It is not a
full security audit and cannot see what is behind your login pages or inside your servers.
A good grade does not mean the site is unhackable; a poor one is a to-do list, not a verdict.
Made by Chase Builds.</footer>
</div></main></body></html>
"""


def to_json(report: Report) -> str:
    return json.dumps(report.to_dict(), indent=2)
