"""Minimal HTTP client: one request at a time, never follows redirects on its own."""

from __future__ import annotations

import http.client
import ssl
import time
from dataclasses import dataclass, field
from urllib.parse import urlsplit

USER_AGENT = (
    "sitecheck/0.1 (passive security checkup; +https://github.com/chasebuilds/site-security-check)"
)
MAX_BODY = 512 * 1024


class FetchError(Exception):
    """The request could not be completed (DNS, refused, timeout)."""


@dataclass
class Response:
    url: str
    status: int
    headers: list[tuple[str, str]] = field(default_factory=list)
    body: str = ""

    def header(self, name: str) -> str | None:
        found = self.header_all(name)
        return found[0] if found else None

    def header_all(self, name: str) -> list[str]:
        return [v for k, v in self.headers if k.lower() == name.lower()]


class Fetcher:
    def __init__(self, timeout: float = 10.0, delay: float = 0.5, cafile: str | None = None):
        self.timeout = timeout
        self.delay = delay
        self.cafile = cafile
        self.count = 0
        self.verify = True

    def _context(self) -> ssl.SSLContext:
        ctx = ssl.create_default_context(cafile=self.cafile)
        if not self.verify:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        return ctx

    def request(self, method: str, url: str, read_body: bool = False) -> Response:
        parts = urlsplit(url)
        host = parts.hostname or ""
        path = (parts.path or "/") + (f"?{parts.query}" if parts.query else "")
        conn: http.client.HTTPConnection
        if parts.scheme == "https":
            conn = http.client.HTTPSConnection(
                host, parts.port, timeout=self.timeout, context=self._context()
            )
        else:
            conn = http.client.HTTPConnection(host, parts.port, timeout=self.timeout)
        if self.count and self.delay:
            time.sleep(self.delay)
        self.count += 1
        try:
            conn.request(method, path, headers={"User-Agent": USER_AGENT, "Accept": "*/*"})
            resp = conn.getresponse()
            body = ""
            if read_body and method == "GET":
                body = resp.read(MAX_BODY).decode("utf-8", errors="replace")
            return Response(url, resp.status, list(resp.getheaders()), body)
        except ssl.SSLCertVerificationError:
            raise
        except (OSError, http.client.HTTPException) as exc:
            raise FetchError(f"{type(exc).__name__}: {exc}") from exc
        finally:
            conn.close()
