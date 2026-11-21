"""Certificate check: one TLS handshake, no HTTP request."""

from __future__ import annotations

import socket
import ssl
from datetime import UTC, datetime
from typing import Any

from .advice import make
from .models import Finding


def check_tls(host: str, port: int, cafile: str | None = None, timeout: float = 10.0) -> Finding:
    ctx = ssl.create_default_context(cafile=cafile)
    try:
        with (
            socket.create_connection((host, port), timeout=timeout) as raw,
            ctx.wrap_socket(raw, server_hostname=host) as tls,
        ):
            cert = tls.getpeercert() or {}
            version = tls.version() or "unknown"
    except ssl.SSLCertVerificationError as exc:
        return make("tls-certificate", "fail", f"Certificate is not trusted: {exc.verify_message}.")
    except OSError as exc:
        return make("tls-certificate", "fail", f"Could not complete a secure connection ({exc}).")

    issuer = _name(cert.get("issuer", ()))
    expires = datetime.fromtimestamp(ssl.cert_time_to_seconds(str(cert["notAfter"])), UTC)
    days = (expires - datetime.now(UTC)).days
    base = f"Issued by {issuer}, expires {expires:%Y-%m-%d} ({days} days left), {version}."
    if days < 0:
        return make("tls-certificate", "fail", f"Certificate expired {-days} days ago. {base}")
    if days < 14:
        return make("tls-certificate", "fail", f"Expires very soon. {base}")
    if days < 30:
        return make("tls-certificate", "warn", f"Expires within a month. {base}")
    return make("tls-certificate", "pass", base)


def _name(rdns: Any) -> str:
    flat = {k: v for rdn in rdns for k, v in rdn}
    return str(flat.get("organizationName") or flat.get("commonName") or "unknown issuer")
