"""Build docs/sample-report.html from a local, deliberately weak test server.

No real site is contacted. Run from the repo root: python examples/make_sample.py
"""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tests"))

from servers import MIXED_HTML, Route, Site, make_cert, serve, strong_site  # noqa: E402
from sitecheck.report import to_html, to_json  # noqa: E402
from sitecheck.scanner import Options, scan  # noqa: E402


def sample_site() -> Site:
    site = strong_site(
        MIXED_HTML.replace("<head>", "<head><meta name='generator' content='WordPress 5.2.4'>")
    )
    root = site.routes["/"]
    root.headers = [
        ("Server", "Apache/2.4.29 (Ubuntu)"),
        ("Strict-Transport-Security", "max-age=300"),
        ("X-Content-Type-Options", "nosniff"),
        ("Set-Cookie", "session=demo; Path=/; Secure"),
    ]
    site.routes["/.env"] = Route(200, [], "DEMO=1")
    del site.routes["/.well-known/security.txt"]
    return site


def dns(name: str) -> list[str]:
    return [] if name.startswith("_dmarc.") else ["v=spf1 include:mail.example.test ~all"]


def main() -> None:
    cert = make_cert(Path(tempfile.mkdtemp()))
    with serve(sample_site(), cert) as url:
        report = scan(
            url,
            Options(
                delay=0.0,
                cafile=str(cert),
                http_port=1,
                email_domain="example.test",
                txt_lookup=dns,
            ),
        )
    report.target = "Sample: local test server built to be weak"
    report.notes.append(
        "This is a sample report. It was made against a local test server on the author's "
        "machine, not against a real website."
    )
    out = ROOT / "docs"
    out.mkdir(exist_ok=True)
    (out / "sample-report.html").write_text(to_html(report), encoding="utf-8")
    (out / "sample-report.json").write_text(to_json(report), encoding="utf-8")
    print(report.grade, report.score)


if __name__ == "__main__":
    main()
