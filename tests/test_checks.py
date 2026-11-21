"""Unit tests for the pure header, HTML and DNS checks."""

from __future__ import annotations

import pytest

from sitecheck import headers
from sitecheck.dns_checks import check_dmarc, check_spf
from sitecheck.html import parse_generator, scan_html
from sitecheck.http import Response


def resp(*pairs: tuple[str, str]) -> Response:
    return Response("https://x/", 200, list(pairs))


def test_hsts_short_max_age_warns() -> None:
    assert (
        headers.check_hsts(resp(("Strict-Transport-Security", "max-age=300")), True).status
        == "warn"
    )
    long = resp(("strict-transport-security", "max-age=31536000"))
    assert headers.check_hsts(long, True).status == "pass"
    assert headers.check_hsts(resp(), True).status == "fail"
    assert headers.check_hsts(resp(), False).status == "fail"


@pytest.mark.parametrize(
    ("csp", "status"),
    [
        ("default-src 'self'", "pass"),
        ("default-src 'self'; script-src 'self' 'unsafe-inline'", "warn"),
        ("script-src *", "warn"),
        ("img-src 'self'", "warn"),
    ],
)
def test_csp(csp: str, status: str) -> None:
    assert headers.check_csp(resp(("Content-Security-Policy", csp))).status == status


def test_csp_missing() -> None:
    assert headers.check_csp(resp()).status == "fail"


def test_framing_accepts_either_header() -> None:
    assert headers.check_framing(resp(("X-Frame-Options", "deny"))).status == "pass"
    csp = resp(("Content-Security-Policy", "frame-ancestors 'none'"))
    assert headers.check_framing(csp).status == "pass"
    assert headers.check_framing(resp(("X-Frame-Options", "ALLOWALL"))).status == "fail"


def test_referrer_unsafe_url_warns() -> None:
    assert headers.check_referrer(resp(("Referrer-Policy", "unsafe-url"))).status == "warn"
    assert headers.check_referrer(resp(("Referrer-Policy", "no-referrer"))).status == "pass"


def test_cookie_flags_on_https() -> None:
    bad = resp(("Set-Cookie", "a=1; Path=/; HttpOnly"))
    f = headers.check_cookies([bad], https=True)
    assert f.status == "fail"
    assert "Secure" in f.summary and "SameSite" in f.summary and "HttpOnly" not in f.summary
    assert "a=1" not in f.summary  # values are never echoed
    good = resp(("Set-Cookie", "a=1; secure; httponly; samesite=strict"))
    assert headers.check_cookies([good], https=True).status == "pass"
    assert headers.check_cookies([resp()], https=True).status == "info"


def test_banner_needs_a_version() -> None:
    assert headers.check_banner(resp(("Server", "nginx"))).status == "pass"
    assert headers.check_banner(resp(("Server", "nginx/1.18.0"))).status == "fail"
    assert headers.check_banner(resp(("X-Powered-By", "Express"))).status == "fail"


def test_html_scan() -> None:
    s = scan_html(
        "<link rel=stylesheet href='http://a/x.css'><link rel=icon href='http://a/i.ico'>"
        "<script src='https://a/ok.js'></script><script src='//a/rel.js'></script>"
        "<img src='HTTP://a/p.png'><meta name=Generator content='Joomla! 3.9'>"
        "<a href='/x'>x</a>"
    )
    assert s.active == ["http://a/x.css"]
    assert s.passive == ["HTTP://a/p.png"]
    assert s.generator == "Joomla! 3.9"
    assert s.links == ["/x"]


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("WordPress 6.4.2", ("wordpress", (6, 4, 2))),
        ("Joomla! 3.9", ("joomla!", (3, 9))),
        ("Hugo", None),
        ("Wix.com Website Builder", None),
    ],
)
def test_parse_generator(text: str, expected: tuple[str, tuple[int, ...]] | None) -> None:
    assert parse_generator(text) == expected


def test_generator_old_version_fails_current_warns_none_passes() -> None:
    old = [scan_html("<meta name=generator content='WordPress 4.9'>")]
    new = [scan_html("<meta name=generator content='WordPress 6.8'>")]
    none = [scan_html("<p>hi</p>")]
    assert headers.check_generator(old).status == "fail"
    assert headers.check_generator(new).status == "warn"
    assert headers.check_generator(none).status == "pass"


def test_spf_variants() -> None:
    def make(records: list[str]):  # type: ignore[no-untyped-def]
        return lambda _n: records

    assert check_spf("d", make([])).status == "fail"
    assert check_spf("d", make(["v=spf1 -all"])).status == "pass"
    assert check_spf("d", make(["v=spf1 ~all"])).status == "pass"
    assert check_spf("d", make(["v=spf1 +all"])).status == "warn"
    assert check_spf("d", make(["google-site-verification=abc"])).status == "fail"


def test_dmarc_variants() -> None:
    asked: list[str] = []

    def lookup(name: str) -> list[str]:
        asked.append(name)
        return ["v=DMARC1; p=none"] if name == "_dmarc.a.test" else []

    assert check_dmarc("a.test", lookup).status == "warn"
    assert asked == ["_dmarc.a.test"]
    assert check_dmarc("b.test", lookup).status == "fail"
    assert check_dmarc("c.test", lambda _n: ["v=DMARC1; p=Quarantine"]).status == "pass"


def test_dns_failure_is_skipped_not_fail() -> None:
    def boom(_n: str) -> list[str]:
        raise OSError("timeout")

    assert check_spf("a.test", boom).status == "skipped"
    assert check_dmarc("a.test", boom).status == "skipped"
