"""Local test servers on 127.0.0.1. Tests and the sample-report script use only these."""

from __future__ import annotations

import datetime as dt
import ipaddress
import ssl
import tempfile
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

Header = tuple[str, str]


@dataclass
class Route:
    status: int = 200
    headers: list[Header] = field(default_factory=list)
    body: str = ""


@dataclass
class Site:
    routes: dict[str, Route] = field(default_factory=dict)
    headers: list[Header] = field(default_factory=list)  # added to every response
    catch_all_200: bool = False
    hits: list[tuple[str, str]] = field(default_factory=list)  # (method, path), filled by server


WEAK_HTML = (
    "<html><head><meta name='generator' content='WordPress 4.9.8'></head><body>"
    "<a href='/about'>About</a><a href='/contact'>Contact</a><a href='/blog'>Blog</a>"
    "<a href='/extra'>Extra</a></body></html>"
)
MIXED_HTML = (
    "<html><head><script src='http://cdn.example.test/a.js?x=1'></script></head><body>"
    "<img src='http://cdn.example.test/p.png'><a href='/about'>About</a></body></html>"
)
CLEAN_HTML = "<html><body><h1>Hello</h1><a href='/about'>About</a></body></html>"


def weak_site() -> Site:
    return Site(
        routes={
            "/": Route(
                200,
                [
                    ("Server", "Apache/2.2.15 (CentOS)"),
                    ("X-Powered-By", "PHP/5.3.3"),
                    ("Set-Cookie", "sid=abc123; Path=/"),
                ],
                WEAK_HTML,
            ),
            "/.env": Route(200, [], "SECRET=1"),
            "/.git/HEAD": Route(200, [], "ref: refs/heads/main"),
            "/about": Route(200, [], "about"),
            "/contact": Route(200, [], "contact"),
            "/blog": Route(200, [], "blog"),
            "/extra": Route(200, [], "extra"),
        }
    )


def strong_site(html: str = CLEAN_HTML) -> Site:
    return Site(
        routes={
            "/": Route(
                200,
                [
                    ("Server", "nginx"),
                    ("Strict-Transport-Security", "max-age=31536000; includeSubDomains"),
                    ("Content-Security-Policy", "default-src 'self'; frame-ancestors 'self'"),
                    ("X-Content-Type-Options", "nosniff"),
                    ("Referrer-Policy", "strict-origin-when-cross-origin"),
                    ("Permissions-Policy", "camera=(), microphone=()"),
                    ("Set-Cookie", "sid=abc; Path=/; Secure; HttpOnly; SameSite=Lax"),
                ],
                html,
            ),
            "/about": Route(200, [], "about"),
            "/.well-known/security.txt": Route(
                200, [], "Contact: mailto:security@example.test\nExpires: 2030-01-01T00:00:00Z\n"
            ),
        }
    )


def _handler(site: Site) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        def _serve(self, head: bool) -> None:
            path = self.path.split("?")[0]
            site.hits.append(("HEAD" if head else "GET", path))
            route = site.routes.get(path)
            if route is None:
                route = Route(200, [], "soft") if site.catch_all_200 else Route(404, [], "no")
            body = route.body.encode()
            self.send_response_only(route.status)
            for k, v in [*site.headers, *route.headers]:
                self.send_header(k, v)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            if not head:
                self.wfile.write(body)

        def do_GET(self) -> None:  # noqa: N802
            self._serve(False)

        def do_HEAD(self) -> None:  # noqa: N802
            self._serve(True)

        def log_message(self, format: str, *args: object) -> None:  # noqa: A002
            pass

    return Handler


def make_cert(directory: Path, valid_days: int = 90) -> Path:
    """Self-signed cert for 127.0.0.1. The same file is the key, cert and trust anchor."""
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, "127.0.0.1"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Test CA"),
        ]
    )
    now = dt.datetime.now(dt.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(days=max(1, 400 - valid_days)))
        .not_valid_after(now + dt.timedelta(days=valid_days))
        .add_extension(
            x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]),
            critical=False,
        )
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    pem = directory / f"cert-{valid_days}.pem"
    pem.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        + cert.public_bytes(serialization.Encoding.PEM)
    )
    return pem


@contextmanager
def serve(site: Site, cert: Path | None = None) -> Iterator[str]:
    """Run the site on a free local port; yield its base URL."""
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), _handler(site))
    scheme = "http"
    if cert:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(cert)
        httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
        scheme = "https"
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"{scheme}://127.0.0.1:{httpd.server_address[1]}"
    finally:
        httpd.shutdown()
        httpd.server_close()
        thread.join(timeout=5)


def temp_dir() -> Path:
    return Path(tempfile.mkdtemp(prefix="sitecheck-test-"))
