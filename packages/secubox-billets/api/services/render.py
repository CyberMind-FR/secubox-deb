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

_MD = MarkdownIt("commonmark", {"html": False, "linkify": True, "typographer": False})
_MD.enable("linkify")

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
