"""Command line: sitecheck https://example.com --i-have-permission"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__
from .report import to_html, to_json
from .scanner import Options, ScanError, scan

PERMISSION_MESSAGE = (
    "Refusing to run. sitecheck sends real requests to the site you name, so use it only on "
    "sites you own or have written permission to check.\n"
    "If that is true, add --i-have-permission."
)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="sitecheck",
        description="Passive website security checkup. Only for sites you own or have written "
        "permission to check.",
    )
    p.add_argument("url", help="site to check, for example https://example.com")
    p.add_argument(
        "--i-have-permission",
        action="store_true",
        help="required: confirms you own the site or have written permission to check it",
    )
    p.add_argument("--html", default="report.html", metavar="FILE", help="HTML report path")
    p.add_argument("--json", default="report.json", metavar="FILE", help="JSON report path")
    p.add_argument("--max-pages", type=int, default=3, help="pages to read, homepage included")
    p.add_argument("--delay", type=float, default=0.5, help="seconds between requests")
    p.add_argument("--timeout", type=float, default=10.0, help="seconds per request")
    p.add_argument("--email-domain", help="domain for SPF/DMARC if different from the site host")
    p.add_argument("--version", action="version", version=f"sitecheck {__version__}")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if not args.i_have_permission:
        print(PERMISSION_MESSAGE, file=sys.stderr)
        return 2
    opts = Options(
        max_pages=max(1, args.max_pages),
        delay=max(0.0, args.delay),
        timeout=args.timeout,
        email_domain=args.email_domain,
    )
    try:
        report = scan(args.url, opts)
    except ScanError as exc:
        print(f"sitecheck: {exc}", file=sys.stderr)
        return 3
    Path(args.html).write_text(to_html(report), encoding="utf-8")
    Path(args.json).write_text(to_json(report), encoding="utf-8")
    fails = sum(1 for f in report.findings if f.status == "fail")
    print(
        f"Grade {report.grade} ({report.score}/100), {fails} to fix, "
        f"{report.requests_made} requests. Wrote {args.html} and {args.json}."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
