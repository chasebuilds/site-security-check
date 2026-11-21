"""Tiny HTML scan: links, loaded resources and the generator meta tag."""

from __future__ import annotations

import re
from html.parser import HTMLParser

_RESOURCE_ATTRS = {
    "script": "src",
    "img": "src",
    "iframe": "src",
    "audio": "src",
    "video": "src",
    "source": "src",
    "embed": "src",
    "link": "href",
}
_PASSIVE = {"img", "audio", "video", "source"}


class PageScan(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.links: list[str] = []
        self.active: list[str] = []  # scripts, frames, stylesheets
        self.passive: list[str] = []  # images, media
        self.generator: str | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        a = {k.lower(): (v or "") for k, v in attrs}
        if tag == "a" and a.get("href"):
            self.links.append(a["href"])
        elif tag == "meta" and a.get("name", "").lower() == "generator":
            self.generator = a.get("content") or None
        elif tag in _RESOURCE_ATTRS:
            if tag == "link" and "stylesheet" not in a.get("rel", "").lower():
                return
            url = a.get(_RESOURCE_ATTRS[tag], "")
            if url.lower().startswith("http://"):
                (self.passive if tag in _PASSIVE else self.active).append(url)


def scan_html(body: str) -> PageScan:
    scan = PageScan()
    scan.feed(body)
    return scan


def parse_generator(text: str) -> tuple[str, tuple[int, ...]] | None:
    """Turn 'WordPress 5.2.1' into ('wordpress', (5, 2, 1)); None when no version is shown."""
    m = re.match(r"\s*([A-Za-z][A-Za-z! ]*?)\s+v?(\d+(?:\.\d+)*)", text)
    if not m:
        return None
    return m.group(1).strip().lower(), tuple(int(p) for p in m.group(2).split("."))
