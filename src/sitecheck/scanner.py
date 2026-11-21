"""Runs every check against one site and builds the report."""

from __future__ import annotations

import ipaddress
import secrets
import ssl
from dataclasses import dataclass, field
from datetime import UTC, datetime
from urllib.parse import urljoin, urlsplit, urlunsplit
from urllib.robotparser import RobotFileParser

from . import headers
from .advice import make
from .dns_checks import TxtLookup, check_dmarc, check_spf, dns_txt
from .html import PageScan, scan_html
from .http import Fetcher, FetchError, Response
from .models import Finding, Report
from .tls import check_tls

EXPOSED_PATHS = ("/.git/HEAD", "/.env", "/wp-config.php.bak", "/server-status")
_SKIP_EXT = {
    ".pdf",
    ".jpg",
    ".jpeg",
    ".png",
    ".gif",
    ".webp",
    ".svg",
    ".zip",
    ".mp4",
    ".mp3",
    ".css",
    ".js",
}


class ScanError(Exception):
    """The scan could not run (bad URL, site unreachable, or robots.txt says no)."""


@dataclass
class Options:
    max_pages: int = 3
    delay: float = 0.5
    timeout: float = 10.0
    cafile: str | None = None
    http_port: int | None = None  # port for the http:// redirect check; default 80
    email_domain: str | None = None
    txt_lookup: TxtLookup = field(default=dns_txt)


def normalize(url: str) -> str:
    if "://" not in url:
        url = "https://" + url
    parts = urlsplit(url)
    if parts.scheme not in {"http", "https"} or not parts.hostname:
        raise ScanError(f"Not a usable web address: {url}")
    return urlunsplit((parts.scheme, parts.netloc, parts.path or "/", "", ""))


def _origin(url: str) -> tuple[str, str, int]:
    p = urlsplit(url)
    return p.scheme, p.hostname or "", p.port or (443 if p.scheme == "https" else 80)


class _Scan:
    def __init__(self, url: str, opts: Options):
        self.opts = opts
        self.url = normalize(url)
        self.fetch = Fetcher(opts.timeout, opts.delay, opts.cafile)
        self.notes: list[str] = []

    def get(self, url: str, body: bool = True) -> Response:
        try:
            return self.fetch.request("GET", url, read_body=body)
        except ssl.SSLCertVerificationError:
            if not self.fetch.verify:
                raise
            self.fetch.verify = False
            self.notes.append(
                "The certificate was not trusted, so page checks were done without verifying it."
            )
            return self.fetch.request("GET", url, read_body=body)

    def home(self, url: str) -> Response:
        """Fetch the page, following up to 3 redirects that stay on the same site and scheme."""
        for _ in range(4):
            resp = self.get(url)
            loc = resp.header("location")
            if resp.status not in {301, 302, 303, 307, 308} or not loc:
                return resp
            nxt = urljoin(url, loc)
            if _origin(nxt)[:2] != _origin(url)[:2]:
                return resp
            url = nxt
        return resp

    def robots(self, base: str) -> RobotFileParser:
        rp = RobotFileParser()
        try:
            resp = self.get(urljoin(base, "/robots.txt"))
            rp.parse(resp.body.splitlines() if resp.status == 200 else [])
        except (FetchError, ssl.SSLError):
            rp.parse([])
        return rp

    def run(self) -> Report:
        scheme, host, port = _origin(self.url)
        findings: dict[str, Finding] = {}
        base = self.url
        robots = self.robots(base)
        if not robots.can_fetch("sitecheck", urlsplit(base).path or "/"):
            raise ScanError("robots.txt asks automated tools not to fetch this page. Stopping.")
        try:
            resp = self.home(base)
        except (FetchError, ssl.SSLError) as exc:
            raise ScanError(f"Could not reach {base}: {exc}") from exc

        if scheme == "http":
            loc = urljoin(base, resp.header("location") or "")
            if resp.status in {301, 302, 303, 307, 308} and loc.startswith("https://"):
                findings["https-redirect"] = make(
                    "https-redirect", "pass", f"http:// sends visitors to {loc}."
                )
                base = loc
                scheme, host, port = _origin(base)
                resp = self.home(base)
            else:
                findings["https-redirect"] = make(
                    "https-redirect", "fail", "This address is served over plain http:// only."
                )
        else:
            findings["https-redirect"] = self._http_redirect(host)
        https = scheme == "https"

        findings["tls-certificate"] = (
            check_tls(host, port, self.opts.cafile, self.opts.timeout)
            if https
            else make("tls-certificate", "fail", "No secure (HTTPS) version was found.")
        )

        scans = [scan_html(resp.body)]
        pages = [resp]
        for extra_url in self._extra_urls(base, scans[0], robots):
            try:
                extra = self.get(extra_url)
            except (FetchError, ssl.SSLError):
                continue
            pages.append(extra)
            scans.append(scan_html(extra.body))

        findings["hsts"] = headers.check_hsts(resp, https)
        findings["csp"] = headers.check_csp(resp)
        findings["framing"] = headers.check_framing(resp)
        findings["nosniff"] = headers.check_nosniff(resp)
        findings["referrer-policy"] = headers.check_referrer(resp)
        findings["permissions-policy"] = headers.check_permissions(resp)
        findings["cookies"] = headers.check_cookies(pages, https)
        findings["server-banner"] = headers.check_banner(resp)
        findings["mixed-content"] = headers.check_mixed(scans, https)
        findings["cms-version"] = headers.check_generator(scans)
        findings["exposed-files"] = self._exposed(base)
        findings["security-txt"] = self._security_txt(base)

        domain = self.opts.email_domain or self._email_domain(host)
        if domain:
            findings["spf"] = check_spf(domain, self.opts.txt_lookup)
            findings["dmarc"] = check_dmarc(domain, self.opts.txt_lookup)
        else:
            for cid in ("spf", "dmarc"):
                findings[cid] = make(cid, "skipped", "Needs a domain name; use --email-domain.")

        return Report(
            target=self.url,
            scanned_at=datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
            findings=list(findings.values()),
            requests_made=self.fetch.count,
            notes=self.notes,
        )

    def _http_redirect(self, host: str) -> Finding:
        port = self.opts.http_port or 80
        url = f"http://{host}:{port}/" if port != 80 else f"http://{host}/"
        try:
            resp = self.fetch.request("HEAD", url)
        except FetchError:
            return make(
                "https-redirect",
                "info",
                "Nothing answers on plain http:// (port closed). "
                "That is fine unless customers type http:// addresses.",
            )
        loc = resp.header("location") or ""
        if resp.status in {301, 302, 303, 307, 308} and loc.lower().startswith("https://"):
            return make("https-redirect", "pass", f"http:// redirects ({resp.status}) to {loc}.")
        return make(
            "https-redirect",
            "fail",
            f"http:// answered {resp.status} and did not redirect to HTTPS.",
        )

    def _extra_urls(self, base: str, scan: PageScan, robots: RobotFileParser) -> list[str]:
        out: list[str] = []
        if self.opts.max_pages <= 1:
            return out
        seen = {urlsplit(base).path or "/"}
        for href in scan.links:
            target = urljoin(base, href.split("#")[0])
            p = urlsplit(target)
            if _origin(target)[:2] != _origin(base)[:2] or p.path in seen:
                continue
            if any(p.path.lower().endswith(e) for e in _SKIP_EXT):
                continue
            if not robots.can_fetch("sitecheck", p.path or "/"):
                continue
            seen.add(p.path)
            out.append(urlunsplit((p.scheme, p.netloc, p.path, "", "")))
            if len(out) >= self.opts.max_pages - 1:
                break
        return out

    def _exposed(self, base: str) -> Finding:
        try:
            baseline = self.fetch.request(
                "HEAD", urljoin(base, f"/sitecheck-{secrets.token_hex(6)}")
            )
            if baseline.status in {200, 206}:
                return make(
                    "exposed-files",
                    "info",
                    "Inconclusive: the site answers 200 for pages that do not exist, "
                    "so file checks cannot be trusted.",
                )
            reachable = []
            for path in EXPOSED_PATHS:
                resp = self.fetch.request("HEAD", urljoin(base, path))
                if resp.status in {200, 206}:
                    reachable.append(path)
        except FetchError as exc:
            return make("exposed-files", "skipped", f"Request failed ({exc}).")
        if reachable:
            return make(
                "exposed-files", "fail", "Reachable from the internet: " + ", ".join(reachable)
            )
        return make(
            "exposed-files",
            "pass",
            "None of the " + str(len(EXPOSED_PATHS)) + " files is reachable.",
        )

    def _security_txt(self, base: str) -> Finding:
        try:
            resp = self.get(urljoin(base, "/.well-known/security.txt"))
        except FetchError:
            return make("security-txt", "skipped", "Request failed.")
        if resp.status == 200 and "contact:" in resp.body.lower():
            return make("security-txt", "pass", "security.txt found with a Contact line.")
        return make("security-txt", "warn", "No security.txt with a Contact line found.")

    @staticmethod
    def _email_domain(host: str) -> str | None:
        try:
            ipaddress.ip_address(host)
            return None
        except ValueError:
            pass
        if "." not in host:
            return None
        return host[4:] if host.startswith("www.") else host


def scan(url: str, opts: Options | None = None) -> Report:
    return _Scan(url, opts or Options()).run()
