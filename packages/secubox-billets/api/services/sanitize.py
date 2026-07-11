# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""Sanitize third-party embed HTML.

Two passes: (1) nh3/ammonia strips scripts, event handlers, javascript: URLs and
anything outside a tight tag/attr allowlist; (2) a targeted iframe pass over the
normalized output enforces that every remaining iframe's src host is on the
provider allowlist, and rewrites it to a canonical form with `sandbox` and
`loading="lazy"` forced (dropping every other iframe attribute). An iframe whose
host is not allowlisted is removed entirely."""
from __future__ import annotations

import re
from html import escape
from urllib.parse import urlparse

import nh3

_EMBED_TAGS = {"iframe", "blockquote", "p", "a", "br", "div", "span", "img",
               "strong", "em", "b", "i"}
_EMBED_ATTRS = {
    "iframe": {"src", "width", "height", "title", "allow", "frameborder", "allowfullscreen"},
    "a": {"href", "title"},
    "img": {"src", "alt", "width", "height"},
    "blockquote": {"cite", "class"},
    "div": {"class"},
    "span": {"class"},
}
_IFRAME_SANDBOX = "allow-scripts allow-same-origin allow-popups allow-presentation"
_IFRAME_RE = re.compile(r"<iframe\b[^>]*>(?:\s*</iframe>)?", re.IGNORECASE | re.DOTALL)


def _attr(tag: str, name: str) -> str | None:
    m = re.search(rf'{name}\s*=\s*"([^"]*)"', tag, re.IGNORECASE)
    if not m:
        m = re.search(rf"{name}\s*=\s*'([^']*)'", tag, re.IGNORECASE)
    return m.group(1) if m else None


def _host_of(url: str) -> str | None:
    try:
        h = urlparse(url).hostname
        return h.lower() if h else None
    except ValueError:
        return None


def _host_allowed(host: str | None, allowed: set[str]) -> bool:
    if not host:
        return False
    host = host.lower()
    return any(host == d or host.endswith("." + d) for d in allowed)


def _harden_iframes(html: str, allowed_hosts: set[str]) -> str:
    def repl(m: re.Match) -> str:
        tag = m.group(0)
        src = _attr(tag, "src") or ""
        if not src.lower().startswith("https://") or not _host_allowed(_host_of(src), allowed_hosts):
            return ""  # drop iframes to non-allowlisted hosts entirely
        width = _attr(tag, "width") or "560"
        height = _attr(tag, "height") or "315"
        title = _attr(tag, "title") or "contenu embarqué"
        return (
            f'<iframe src="{escape(src, quote=True)}" '
            f'width="{escape(width, quote=True)}" height="{escape(height, quote=True)}" '
            f'title="{escape(title, quote=True)}" loading="lazy" '
            f'sandbox="{_IFRAME_SANDBOX}" referrerpolicy="no-referrer" '
            f'allowfullscreen></iframe>'
        )
    return _IFRAME_RE.sub(repl, html)


def sanitize_embed(html: str, allowed_hosts: set[str]) -> str:
    cleaned = nh3.clean(
        html or "",
        tags=_EMBED_TAGS,
        attributes=_EMBED_ATTRS,
        url_schemes={"https"},
        link_rel="nofollow ugc noopener noreferrer",
        strip_comments=True,
    )
    return _harden_iframes(cleaned, allowed_hosts)
