# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""Restricted-markdown → safe HTML.

Billet bodies are markdown limited to bold, italic, links, lists and
blockquote — never raw HTML. We render with markdown-it (HTML disabled) and
then hard-sanitize with nh3 (ammonia) against a tight allowlist, so even if the
renderer ever emitted a tag we don't want, it cannot survive. Links get
rel="nofollow ugc noopener noreferrer"."""
from __future__ import annotations

import nh3
from markdown_it import MarkdownIt

# linkify (bare-URL autolinking) is intentionally OFF: it needs the optional
# linkify-it-py package, and the spec only requires markdown links [text](url).
# Bare URLs in *comments* are autolinked separately in `linkify_plain`.
_MD = MarkdownIt("commonmark", {"html": False, "linkify": False, "typographer": False})

_ALLOWED_TAGS = {
    "p", "br", "strong", "em", "b", "i", "a",
    "ul", "ol", "li", "blockquote", "code", "pre",
}
_ALLOWED_ATTRS = {"a": {"href", "title"}}
_LINK_REL = "nofollow ugc noopener noreferrer"


def render_markdown(text: str) -> str:
    """Render restricted markdown to sanitized HTML (safe to mark |safe in Jinja)."""
    html = _MD.render(text or "")
    return nh3.clean(
        html,
        tags=_ALLOWED_TAGS,
        attributes=_ALLOWED_ATTRS,
        link_rel=_LINK_REL,
        url_schemes={"http", "https", "mailto"},
    )


import html as _htmlmod  # noqa: E402
import re as _re  # noqa: E402

_URL_RE = _re.compile(r"(https?://[^\s<]+)")


def linkify_plain(text: str) -> str:
    """Comment bodies: escape as plain text (no markdown, no HTML), then
    auto-link bare URLs with rel="nofollow ugc". Safe to mark |safe."""
    escaped = _htmlmod.escape(text or "")

    def _repl(m: "_re.Match") -> str:
        url = m.group(1)
        return f'<a href="{url}" rel="nofollow ugc noopener noreferrer">{url}</a>'

    return _URL_RE.sub(_repl, escaped).replace("\n", "<br>")
