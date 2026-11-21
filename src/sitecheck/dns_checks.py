"""SPF and DMARC: two DNS TXT lookups."""

from __future__ import annotations

from collections.abc import Callable

import dns.exception
import dns.resolver

from .advice import make
from .models import Finding

TxtLookup = Callable[[str], list[str]]


def dns_txt(name: str) -> list[str]:
    try:
        answers = dns.resolver.resolve(name, "TXT", lifetime=5.0)
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        return []
    except dns.exception.DNSException as exc:
        raise OSError(str(exc)) from exc
    return [b"".join(r.strings).decode("utf-8", errors="replace") for r in answers]


def check_spf(domain: str, lookup: TxtLookup) -> Finding:
    try:
        records = [r for r in lookup(domain) if r.lower().startswith("v=spf1")]
    except OSError as exc:
        return make("spf", "skipped", f"DNS lookup failed ({exc}).")
    if not records:
        return make("spf", "fail", f"No SPF record found for {domain}.")
    spf = records[0].lower()
    if spf.endswith("-all"):
        return make("spf", "pass", f"SPF found and ends in a hard fail: {records[0]}")
    if spf.endswith("~all"):
        return make("spf", "pass", f"SPF found with soft fail (~all): {records[0]}")
    return make("spf", "warn", f"SPF found but it does not end in -all or ~all: {records[0]}")


def check_dmarc(domain: str, lookup: TxtLookup) -> Finding:
    try:
        records = [r for r in lookup(f"_dmarc.{domain}") if r.lower().startswith("v=dmarc1")]
    except OSError as exc:
        return make("dmarc", "skipped", f"DNS lookup failed ({exc}).")
    if not records:
        return make("dmarc", "fail", f"No DMARC record found at _dmarc.{domain}.")
    tags = {
        k.strip().lower(): v.strip().lower()
        for k, _, v in (p.partition("=") for p in records[0].split(";"))
    }
    policy = tags.get("p", "")
    if policy in {"quarantine", "reject"}:
        return make("dmarc", "pass", f"DMARC policy is p={policy}.")
    return make(
        "dmarc", "warn", "DMARC exists but p=none only monitors; fakes are still delivered."
    )
