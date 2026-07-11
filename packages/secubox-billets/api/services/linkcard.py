# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""OpenGraph link-card fallback for URLs with no (working) oEmbed.

Fetches the page through the SSRF-guarded client, reads og:title / og:description
/ og:image, and renders a LOCAL HTML card — never an iframe, never remote HTML.
All extracted values are escaped; og:image must be an https URL or it is dropped."""
from __future__ import annotations

import re
from html import escape
from urllib.parse import urlparse

import httpx

from . import ssrf

_META_RE = re.compile(r"<meta\b[^>]*>", re.IGNORECASE)
_PROP_RE = re.compile(r'(?:property|name)\s*=\s*["\']([^"\']+)["\']', re.IGNORECASE)
_CONTENT_RE = re.compile(r'content\s*=\s*["\']([^"\']*)["\']', re.IGNORECASE)
_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)
_MAX_FIELD = 400


def _og(text: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for tag in _META_RE.findall(text):
        prop = _PROP_RE.search(tag)
        content = _CONTENT_RE.search(tag)
        if prop and content:
            key = prop.group(1).lower()
            if key in ("og:title", "og:description", "og:image", "twitter:title",
                       "twitter:description", "twitter:image", "description"):
                out.setdefault(key, content.group(1))
    return out


def _https(url: str | None) -> str | None:
    if url and url.lower().startswith("https://"):
        return url
    return None


def build_card(url: str, title: str, description: str, image: str | None) -> str:
    host = urlparse(url).hostname or url
    img = (f'<img class="card-img" src="{escape(image, quote=True)}" alt="" loading="lazy">'
           if image else "")
    return (
        f'<a class="link-card" href="{escape(url, quote=True)}" '
        f'rel="nofollow ugc noopener noreferrer" target="_blank">'
        f'{img}<span class="card-body">'
        f'<span class="card-title">{escape(title)}</span>'
        f'<span class="card-desc">{escape(description)}</span>'
        f'<span class="card-host">{escape(host)}</span></span></a>'
    )


async def fetch_card(url: str, *, client: httpx.AsyncClient, resolver=ssrf._default_resolver
                     ) -> dict | None:
    """Return {"provider": "link", "html": <card>, "kind": "linkcard"} or None."""
    try:
        final_url, ctype, body = await ssrf.fetch(url, client=client, resolver=resolver)
    except ssrf.SSRFError:
        return None
    if "html" not in ctype and body[:1] != b"<":
        return None
    text = body.decode("utf-8", "replace")
    og = _og(text)
    title = og.get("og:title") or og.get("twitter:title") or ""
    if not title:
        tm = _TITLE_RE.search(text)
        title = (tm.group(1).strip() if tm else "") or (urlparse(url).hostname or url)
    desc = og.get("og:description") or og.get("twitter:description") or og.get("description") or ""
    image = _https(og.get("og:image") or og.get("twitter:image"))
    html = build_card(url, title[:_MAX_FIELD], desc[:_MAX_FIELD], image)
    return {"provider": "link", "html": html, "kind": "linkcard"}


async def resolve_embed(url: str, *, client: httpx.AsyncClient, resolver=ssrf._default_resolver
                        ) -> dict:
    """Full pipeline: oEmbed (allowlist/discovery) then link-card fallback.

    Always returns a dict with kind in {oembed, linkcard, none}; never raises."""
    from .oembed import resolve_oembed
    try:
        emb = await resolve_oembed(url, client=client, resolver=resolver)
        if emb:
            return emb
        card = await fetch_card(url, client=client, resolver=resolver)
        if card:
            return card
    except Exception:  # noqa: BLE001 — embedding must never break a publish
        pass
    return {"provider": None, "html": "", "kind": "none"}
