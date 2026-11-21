"""End-to-end scans against local servers on 127.0.0.1. Nothing here touches the internet."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from servers import (
    MIXED_HTML,
    Route,
    Site,
    make_cert,
    serve,
    strong_site,
    weak_site,
)
from sitecheck.cli import main
from sitecheck.models import Finding, Report
from sitecheck.scanner import Options, ScanError, scan


def good_dns(name: str) -> list[str]:
    if name.startswith("_dmarc."):
        return ["v=DMARC1; p=reject; rua=mailto:d@example.test"]
    return ["v=spf1 include:mail.example.test -all"]


def by_id(report: Report) -> dict[str, Finding]:
    return {f.id: f for f in report.findings}


def opts(**kw: object) -> Options:
    base: dict[str, object] = {
        "delay": 0.0,
        "timeout": 5.0,
        "email_domain": "example.test",
        "txt_lookup": good_dns,
    }
    base.update(kw)
    return Options(**base)  # type: ignore[arg-type]


@pytest.fixture(scope="module")
def cert(tmp_path_factory: pytest.TempPathFactory) -> Path:
    return make_cert(tmp_path_factory.mktemp("certs"))


def test_weak_site_fails_the_right_checks() -> None:
    site = weak_site()
    with serve(site) as url:
        report = scan(url, opts(txt_lookup=lambda _n: []))
    f = by_id(report)
    for cid in (
        "https-redirect",
        "tls-certificate",
        "hsts",
        "csp",
        "framing",
        "nosniff",
        "referrer-policy",
        "permissions-policy",
        "cookies",
        "server-banner",
        "cms-version",
        "exposed-files",
        "spf",
        "dmarc",
    ):
        assert f[cid].status == "fail", cid
    assert "/.env" in f["exposed-files"].summary
    assert "/.git/HEAD" in f["exposed-files"].summary
    assert "/server-status" not in f["exposed-files"].summary
    assert "wp-config" not in f["exposed-files"].summary
    assert "sid lacks HttpOnly, SameSite" in f["cookies"].summary  # no Secure needed on http
    assert f["mixed-content"].status == "skipped"
    assert report.grade == "F"


def test_weak_site_makes_only_expected_requests() -> None:
    site = weak_site()
    with serve(site) as url:
        report = scan(url, opts())
    allowed = {
        "/",
        "/robots.txt",
        "/about",
        "/contact",
        "/.env",
        "/.git/HEAD",
        "/wp-config.php.bak",
        "/server-status",
        "/.well-known/security.txt",
    }
    paths = [p for _, p in site.hits]
    assert all(p in allowed or p.startswith("/sitecheck-") for p in paths), paths
    assert len(site.hits) == report.requests_made
    assert len(paths) == len(set(paths)), "same path requested twice"
    heads = {p for m, p in site.hits if m == "HEAD"}
    assert {"/.env", "/.git/HEAD", "/wp-config.php.bak", "/server-status"} <= heads
    assert all(m == "HEAD" for m, p in site.hits if p in {"/.env", "/.git/HEAD", "/server-status"})


def test_max_pages_limits_crawl() -> None:
    site = weak_site()
    with serve(site) as url:
        scan(url, opts(max_pages=1))
    assert not {"/about", "/contact", "/blog"} & {p for _, p in site.hits}
    site2 = weak_site()
    with serve(site2) as url:
        scan(url, opts(max_pages=2))
    pages = [p for m, p in site2.hits if m == "GET" and p in {"/about", "/contact", "/blog"}]
    assert pages == ["/about"]


def test_strong_site_scores_an_a(cert: Path) -> None:
    with serve(strong_site(), cert) as https_url:
        port = https_url.rsplit(":", 1)[1]
        redirect = Site(routes={"/": Route(301, [("Location", f"https://127.0.0.1:{port}/")])})
        with serve(redirect) as http_url:
            report = scan(
                https_url, opts(cafile=str(cert), http_port=int(http_url.rsplit(":", 1)[1]))
            )
    f = by_id(report)
    bad = {k: v.summary for k, v in f.items() if v.status in {"fail", "warn"}}
    assert bad == {}
    assert report.grade == "A"
    assert report.score == 100
    assert "Test CA" in f["tls-certificate"].summary


def test_http_url_that_redirects_continues_on_https(cert: Path) -> None:
    with serve(strong_site(), cert) as https_url:
        port = https_url.rsplit(":", 1)[1]
        redirect = Site(routes={"/": Route(301, [("Location", f"https://127.0.0.1:{port}/")])})
        with serve(redirect) as http_url:
            report = scan(http_url, opts(cafile=str(cert)))
    f = by_id(report)
    assert f["https-redirect"].status == "pass"
    assert f["hsts"].status == "pass"
    assert f["tls-certificate"].status == "pass"


def test_untrusted_certificate_is_reported(cert: Path) -> None:
    with serve(strong_site(), cert) as url:
        report = scan(url, opts(http_port=1))  # no cafile: self-signed is not trusted
    f = by_id(report)
    assert f["tls-certificate"].status == "fail"
    assert "not trusted" in f["tls-certificate"].summary
    assert any("not trusted" in n for n in report.notes)
    assert f["hsts"].status == "pass"  # headers were still read


@pytest.mark.parametrize(("days", "status"), [(5, "fail"), (20, "warn"), (60, "pass")])
def test_certificate_expiry_thresholds(tmp_path: Path, days: int, status: str) -> None:
    pem = make_cert(tmp_path, valid_days=days)
    with serve(strong_site(), pem) as url:
        report = scan(url, opts(cafile=str(pem), http_port=1))
    assert by_id(report)["tls-certificate"].status == status


def test_mixed_content_found_on_https(cert: Path) -> None:
    with serve(strong_site(MIXED_HTML), cert) as url:
        report = scan(url, opts(cafile=str(cert), http_port=1))
    f = by_id(report)["mixed-content"]
    assert f.status == "fail"
    assert "1 script/style/frame and 1 image" in f.summary
    assert "?x=1" not in f.summary  # query strings are not echoed


def test_robots_disallow_stops_scan() -> None:
    site = weak_site()
    site.routes["/robots.txt"] = Route(200, [], "User-agent: *\nDisallow: /\n")
    with serve(site) as url, pytest.raises(ScanError, match="robots.txt"):
        scan(url, opts())
    assert [p for _, p in site.hits] == ["/robots.txt"]


def test_robots_disallow_skips_one_section() -> None:
    site = weak_site()
    site.routes["/robots.txt"] = Route(200, [], "User-agent: *\nDisallow: /about\n")
    with serve(site) as url:
        scan(url, opts())
    assert "/about" not in {p for _, p in site.hits}
    assert "/contact" in {p for _, p in site.hits}


def test_soft_404_makes_file_check_inconclusive() -> None:
    site = weak_site()
    site.catch_all_200 = True
    with serve(site) as url:
        report = scan(url, opts())
    f = by_id(report)["exposed-files"]
    assert f.status == "info"
    assert "Inconclusive" in f.summary
    assert report.grade != "D" or report.score < 60


def test_exposed_file_caps_grade_at_d() -> None:
    report = Report("t", "now", [Finding("exposed-files", "x", "fail", 20, "s", "m", "f")])
    assert report.score == 80
    assert report.grade == "D"


def test_unreachable_site_raises() -> None:
    with pytest.raises(ScanError, match="Could not reach"):
        scan("http://127.0.0.1:1", opts())


def test_bad_url_raises() -> None:
    with pytest.raises(ScanError):
        scan("ftp://example.test", opts())


def test_cli_requires_permission_flag(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    site = weak_site()
    with serve(site) as url:
        code = main([url, "--html", str(tmp_path / "r.html")])
    assert code == 2
    assert site.hits == []
    assert "written permission" in capsys.readouterr().err
    assert not (tmp_path / "r.html").exists()


def test_cli_writes_reports(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    site = weak_site()
    out_html, out_json = tmp_path / "r.html", tmp_path / "r.json"
    with serve(site) as url:
        code = main(
            [
                url,
                "--i-have-permission",
                "--delay",
                "0",
                "--email-domain",
                "",
                "--html",
                str(out_html),
                "--json",
                str(out_json),
            ]
        )
    assert code == 0
    data = json.loads(out_json.read_text(encoding="utf-8"))
    assert data["grade"] == "F"
    assert {f["id"] for f in data["findings"]} >= {"hsts", "csp", "exposed-files", "spf"}
    html = out_html.read_text(encoding="utf-8")
    assert "Fix these first" in html
    assert "How to fix it" in html
    assert "Grade F" in capsys.readouterr().out


def test_html_report_escapes_page_content() -> None:
    f = Finding("x", "T<script>", "fail", 5, "<img src=x onerror=alert(1)>", "m", "f")
    from sitecheck.report import to_html

    html = to_html(Report("http://a/<b>", "now", [f]))
    assert "<img src=x" not in html
    assert "<script>" not in html.split("</style>")[1]
