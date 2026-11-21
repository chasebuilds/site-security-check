"""Plain-English explanations. One entry per check: title, weight, what it means, how to fix."""

from __future__ import annotations

from .models import Finding, Status

# id: (title, weight, meaning, fix)
ADVICE: dict[str, tuple[str, int, str, str]] = {
    "https-redirect": (
        "Visitors are sent to the secure (HTTPS) version",
        15,
        "If someone types your address without https, they should be moved to the secure "
        "version automatically. Without that, their traffic can be read or changed on public "
        "Wi-Fi.",
        "Turn on 'Force HTTPS' in your host or CDN, or add a permanent (301) redirect from "
        "http:// to https:// in your web server settings.",
    ),
    "tls-certificate": (
        "Security certificate is valid and not about to expire",
        15,
        "The certificate is what makes the padlock work. An expired or untrusted one makes "
        "browsers show a scary full-page warning and most customers leave.",
        "Renew the certificate. Most hosts renew free certificates (Let's Encrypt) "
        "automatically; check that auto-renewal is switched on.",
    ),
    "hsts": (
        "Browsers are told to always use HTTPS (HSTS)",
        8,
        "The Strict-Transport-Security header tells browsers to refuse the insecure version "
        "of your site for a set time, which blocks downgrade tricks.",
        "Add the header 'Strict-Transport-Security: max-age=31536000; includeSubDomains' "
        "once every page and subdomain works over HTTPS.",
    ),
    "csp": (
        "Content Security Policy limits what the page can load",
        10,
        "A Content Security Policy lists where scripts and images may come from. It is the "
        "main defence that stops injected scripts from stealing data.",
        "Start with a report-only policy, then enforce one such as "
        "\"default-src 'self'\". Avoid 'unsafe-inline' and '*' where you can.",
    ),
    "framing": (
        "Other sites cannot put yours inside a hidden frame",
        6,
        "Without frame protection, another site can show your page invisibly under a fake "
        "button and trick visitors into clicking it (clickjacking).",
        "Send 'X-Frame-Options: SAMEORIGIN' or a CSP rule 'frame-ancestors 'self''.",
    ),
    "nosniff": (
        "Browsers are told not to guess file types",
        5,
        "Without X-Content-Type-Options, some browsers may treat an uploaded file as a "
        "script and run it.",
        "Send the header 'X-Content-Type-Options: nosniff'.",
    ),
    "referrer-policy": (
        "Private page addresses are not leaked to other sites",
        4,
        "Without a Referrer-Policy, the full address of the page a visitor came from "
        "(which can include private details) may be passed to every site you link to.",
        "Send 'Referrer-Policy: strict-origin-when-cross-origin'.",
    ),
    "permissions-policy": (
        "Browser features such as camera and location are restricted",
        3,
        "A Permissions-Policy switches off browser features your site does not use, so a "
        "compromised script cannot turn them on.",
        "Send 'Permissions-Policy: camera=(), microphone=(), geolocation=()' and allow "
        "only what you need.",
    ),
    "cookies": (
        "Cookies carry the right protection flags",
        8,
        "Secure keeps a cookie off insecure connections, HttpOnly hides it from page "
        "scripts, and SameSite limits cross-site use. Missing flags make login cookies "
        "easier to steal.",
        "In your site or framework settings turn on Secure, HttpOnly and "
        "SameSite=Lax (or Strict) for session and login cookies.",
    ),
    "server-banner": (
        "Server does not announce its software version",
        4,
        "Headers such as 'Server: Apache/2.2.15' tell attackers exactly which known bugs to try.",
        "Hide or shorten the banner (for example 'ServerTokens Prod' in Apache or "
        "'server_tokens off' in nginx) and remove X-Powered-By.",
    ),
    "mixed-content": (
        "Secure pages do not load insecure files",
        8,
        "A secure page that pulls in scripts, styles or images over plain http:// can be "
        "tampered with on the way, and browsers may block or warn about it.",
        "Change those http:// links to https:// (or to relative links). Check your page "
        "builder, theme and any hard-coded addresses.",
    ),
    "exposed-files": (
        "Private files are not downloadable",
        20,
        "Files such as .env, .git or backup copies of config files can hold passwords and "
        "source code. If a request for them succeeds, anyone can fetch them.",
        "Remove the file from the public web folder, or block it in the server config, "
        "and then change any password or key that was inside it.",
    ),
    "cms-version": (
        "Site software is not announcing an old version",
        6,
        "Many sites say which CMS and version built them in a hidden tag. An old version "
        "usually has published security holes.",
        "Update the CMS, themes and plugins to the latest release, then remove the "
        "generator tag (most CMSs have a setting or a one-line filter for this).",
    ),
    "security-txt": (
        "A security contact is published (security.txt)",
        2,
        "A small file at /.well-known/security.txt tells researchers where to report a "
        "problem privately instead of posting it or ignoring it.",
        "Create /.well-known/security.txt with a 'Contact:' line (an email or form) and an "
        "'Expires:' date. securitytxt.org has a generator.",
    ),
    "spf": (
        "Email: SPF record limits who can send as your domain",
        5,
        "SPF lists the servers allowed to send email for your domain. Without it, "
        "scammers can send mail that looks like it came from you.",
        "Add a TXT record such as 'v=spf1 include:<your mail provider> -all'. Your email "
        "provider documents the exact value.",
    ),
    "dmarc": (
        "Email: DMARC record tells receivers what to do with fakes",
        5,
        "DMARC tells other mail systems to reject or quarantine mail that fails SPF/DKIM "
        "checks, which stops most look-alike emails.",
        "Add a TXT record at _dmarc.<your domain>, starting with "
        "'v=DMARC1; p=none; rua=mailto:<you>' to watch, then move to p=quarantine and "
        "later p=reject.",
    ),
}


def make(check_id: str, status: Status, summary: str) -> Finding:
    title, weight, meaning, fix = ADVICE[check_id]
    return Finding(check_id, title, status, weight, summary, meaning, fix)
