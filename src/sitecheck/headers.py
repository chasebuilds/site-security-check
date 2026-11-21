"""Checks that only read response headers and the page HTML. No network access here."""

from __future__ import annotations

import re
from urllib.parse import urlsplit

from .advice import make
from .html import PageScan, parse_generator
from .http import Response
from .models import Finding

HSTS_MIN_AGE = 15_552_000  # 180 days

# Oldest release line we treat as still maintained. Small, hand-kept, and it ages: see LIMITATIONS.
MIN_CMS_VERSION: dict[str, tuple[int, ...]] = {
    "wordpress": (6, 0),
    "joomla!": (4, 0),
    "joomla": (4, 0),
    "drupal": (10, 0),
}


def _csp_directives(csp: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for part in csp.split(";"):
        name, _, value = part.strip().partition(" ")
        if name:
            out.setdefault(name.lower(), value.strip())
    return out


def check_hsts(resp: Response, https: bool) -> Finding:
    if not https:
        return make("hsts", "fail", "The site is not served over HTTPS, so HSTS cannot apply.")
    value = resp.header("strict-transport-security")
    if value is None:
        return make("hsts", "fail", "No Strict-Transport-Security header.")
    m = re.search(r"max-age\s*=\s*(\d+)", value, re.I)
    age = int(m.group(1)) if m else 0
    if age < HSTS_MIN_AGE:
        return make("hsts", "warn", f"HSTS is set but max-age={age} is under 180 days.")
    return make("hsts", "pass", f"Present: {value}")


def check_csp(resp: Response) -> Finding:
    value = resp.header("content-security-policy")
    if value is None:
        return make("csp", "fail", "No Content-Security-Policy header.")
    d = _csp_directives(value)
    script = d.get("script-src") or d.get("default-src") or ""
    problems = []
    if "'unsafe-inline'" in script:
        problems.append("allows 'unsafe-inline' scripts")
    if "'unsafe-eval'" in script:
        problems.append("allows 'unsafe-eval'")
    if re.search(r"(^|\s)\*(\s|$)", script):
        problems.append("allows scripts from any site (*)")
    if not script:
        problems.append("sets no script-src or default-src")
    if problems:
        return make("csp", "warn", "A policy is set but it " + ", ".join(problems) + ".")
    return make("csp", "pass", "A policy is set and restricts scripts.")


def check_framing(resp: Response) -> Finding:
    xfo = (resp.header("x-frame-options") or "").strip().upper()
    csp = _csp_directives(resp.header("content-security-policy") or "")
    if "frame-ancestors" in csp:
        return make("framing", "pass", f"CSP frame-ancestors {csp['frame-ancestors']}.")
    if xfo in {"DENY", "SAMEORIGIN"}:
        return make("framing", "pass", f"X-Frame-Options: {xfo}.")
    return make("framing", "fail", "Neither X-Frame-Options nor CSP frame-ancestors is set.")


def check_nosniff(resp: Response) -> Finding:
    value = (resp.header("x-content-type-options") or "").strip().lower()
    if value == "nosniff":
        return make("nosniff", "pass", "X-Content-Type-Options: nosniff.")
    return make("nosniff", "fail", "X-Content-Type-Options: nosniff is missing.")


def check_referrer(resp: Response) -> Finding:
    value = (resp.header("referrer-policy") or "").strip().lower()
    if not value:
        return make("referrer-policy", "fail", "No Referrer-Policy header.")
    if value in {"unsafe-url", "no-referrer-when-downgrade"}:
        return make(
            "referrer-policy", "warn", f"Referrer-Policy is {value}, which leaks full URLs."
        )
    return make("referrer-policy", "pass", f"Referrer-Policy: {value}.")


def check_permissions(resp: Response) -> Finding:
    if resp.header("permissions-policy") or resp.header("feature-policy"):
        return make("permissions-policy", "pass", "A Permissions-Policy is set.")
    return make("permissions-policy", "fail", "No Permissions-Policy header.")


def check_cookies(resp_list: list[Response], https: bool) -> Finding:
    problems: list[str] = []
    seen = 0
    for resp in resp_list:
        for raw in resp.header_all("set-cookie"):
            seen += 1
            name, _, _ = raw.partition("=")
            attrs = {a.strip().lower().split("=")[0] for a in raw.split(";")[1:]}
            missing = []
            if https and "secure" not in attrs:
                missing.append("Secure")
            if "httponly" not in attrs:
                missing.append("HttpOnly")
            if "samesite" not in attrs:
                missing.append("SameSite")
            if missing:
                problems.append(f"{name.strip()} lacks {', '.join(missing)}")
    if not seen:
        return make("cookies", "info", "The pages checked set no cookies.")
    if problems:
        return make("cookies", "fail", f"{seen} cookie(s) set. " + "; ".join(sorted(set(problems))))
    return make("cookies", "pass", f"{seen} cookie(s) set, all with Secure/HttpOnly/SameSite.")


def check_banner(resp: Response) -> Finding:
    leaks = []
    server = resp.header("server")
    if server and re.search(r"\d+\.\d+", server):
        leaks.append(f"Server: {server}")
    for name in ("x-powered-by", "x-aspnet-version", "x-aspnetmvc-version"):
        value = resp.header(name)
        if value:
            leaks.append(f"{name}: {value}")
    if leaks:
        return make("server-banner", "fail", "Software details are visible: " + "; ".join(leaks))
    return make("server-banner", "pass", "No software version appears in the response headers.")


def check_mixed(scans: list[PageScan], https: bool) -> Finding:
    if not https:
        return make("mixed-content", "skipped", "Not relevant: the site is not on HTTPS.")
    active = [u for s in scans for u in s.active]
    passive = [u for s in scans for u in s.passive]
    if not active and not passive:
        return make("mixed-content", "pass", "No http:// scripts, styles, frames or images found.")
    examples = ", ".join(urlsplit(u)._replace(query="").geturl() for u in (active + passive)[:3])
    summary = f"{len(active)} script/style/frame and {len(passive)} image/media link(s): {examples}"
    return make("mixed-content", "fail" if active else "warn", summary)


def check_generator(scans: list[PageScan]) -> Finding:
    text = next((s.generator for s in scans if s.generator), None)
    if not text:
        return make("cms-version", "pass", "No generator tag found.")
    parsed = parse_generator(text)
    if parsed is None:
        return make("cms-version", "pass", f"Generator tag shows '{text}' with no version.")
    name, version = parsed
    minimum = MIN_CMS_VERSION.get(name)
    if minimum and version < minimum:
        floor = ".".join(map(str, minimum))
        return make("cms-version", "fail", f"Generator tag says '{text}', older than {floor}.")
    return make("cms-version", "warn", f"Generator tag reveals '{text}'. Version looks current.")
