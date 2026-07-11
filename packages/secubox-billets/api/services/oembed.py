# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""oEmbed resolution against a provider allowlist, with same-origin discovery
for self-hosted providers (Mastodon, PeerTube, Bandcamp).

Known providers hit a fixed oEmbed endpoint. Unknown hosts are tried via oEmbed
*discovery*: fetch the page, read its `<link rel=...oembed>` — but only if that
endpoint is same-origin as the page (so we never chase an oEmbed endpoint on a
third-party host). Everything returned is run through `sanitize_embed`, whose
iframe host-allowlist is the union of the global embed hosts and (for discovery)
the source host. Anything that fails falls back to a link card upstream."""
from __future__ import annotations

import json
import re
from urllib.parse import quote, urljoin, urlparse

import httpx

from . import ssrf
from .sanitize import sanitize_embed

# host suffix -> (oembed endpoint template, provider label)
_ENDPOINTS: dict[str, tuple[str, str]] = {
    "youtube.com": ("https://www.youtube.com/oembed?format=json&url={url}", "youtube"),
    "youtu.be": ("https://www.youtube.com/oembed?format=json&url={url}", "youtube"),
    "vimeo.com": ("https://vimeo.com/api/oembed.json?url={url}", "vimeo"),
    "twitter.com": ("https://publish.twitter.com/oembed?url={url}", "twitter"),
    "x.com": ("https://publish.twitter.com/oembed?url={url}", "twitter"),
    "bsky.app": ("https://embed.bsky.app/oembed?url={url}", "bluesky"),
    "flickr.com": ("https://www.flickr.com/services/oembed?format=json&url={url}", "flickr"),
    "soundcloud.com": ("https://soundcloud.com/oembed?format=json&url={url}", "soundcloud"),
}

# iframe src hosts allowed globally (registrable-domain suffixes)
GLOBAL_IFRAME_HOSTS = {
    "youtube.com", "youtube-nocookie.com", "youtu.be",
    "vimeo.com", "twitter.com", "x.com", "bsky.app",
    "flickr.com", "soundcloud.com", "bandcamp.com",
}

_OEMBED_LINK_RE = re.compile(
    r'<link[^>]+type=["\']application/(?:json\+oembed|xml\+oembed)["\'][^>]*>',
    re.IGNORECASE)
_HREF_RE = re.compile(r'href=["\']([^"\']+)["\']', re.IGNORECASE)


def _host_of(url: str) -> str | None:
    try:
        h = urlparse(url).hostname
        return h.lower() if h else None
    except ValueError:
        return None


def _match_endpoint(host: str) -> tuple[str, str] | None:
    for suffix, spec in _ENDPOINTS.items():
        if host == suffix or host.endswith("." + suffix):
            return spec
    return None


async def _fetch_json(url: str, *, client: httpx.AsyncClient, resolver) -> dict | None:
    try:
        _, _, body = await ssrf.fetch(url, client=client, resolver=resolver)
        return json.loads(body.decode("utf-8", "replace"))
    except (ssrf.SSRFError, json.JSONDecodeError, UnicodeError):
        return None


async def _discover(page_url: str, host: str, *, client: httpx.AsyncClient, resolver) -> str | None:
    """Return the same-origin oEmbed endpoint declared by a page, or None."""
    try:
        _, ctype, body = await ssrf.fetch(page_url, client=client, resolver=resolver)
    except ssrf.SSRFError:
        return None
    if "html" not in ctype and body[:1] not in (b"<",):
        return None
    text = body.decode("utf-8", "replace")
    m = _OEMBED_LINK_RE.search(text)
    if not m:
        return None
    href_m = _HREF_RE.search(m.group(0))
    if not href_m:
        return None
    endpoint = urljoin(page_url, href_m.group(1).replace("&amp;", "&"))
    if _host_of(endpoint) != host:  # same-origin discovery only
        return None
    return endpoint


async def resolve_oembed(url: str, *, client: httpx.AsyncClient, resolver=ssrf._default_resolver
                         ) -> dict | None:
    """Return {"provider", "html", "kind": "oembed"} or None. HTML is sanitized."""
    host = _host_of(url)
    if not host:
        return None
    allowed = set(GLOBAL_IFRAME_HOSTS)
    spec = _match_endpoint(host)
    if spec:
        endpoint = spec[0].format(url=quote(url, safe=""))
        provider = spec[1]
        data = await _fetch_json(endpoint, client=client, resolver=resolver)
    else:
        endpoint = await _discover(url, host, client=client, resolver=resolver)
        if not endpoint:
            return None
        provider = host
        allowed.add(host)  # self-hosted (Mastodon/PeerTube) iframes are same-origin
        data = await _fetch_json(endpoint, client=client, resolver=resolver)
    if not data or not isinstance(data, dict) or not data.get("html"):
        return None
    html = sanitize_embed(str(data["html"]), allowed)
    if not html.strip():
        return None
    return {"provider": provider, "html": html, "kind": "oembed"}
