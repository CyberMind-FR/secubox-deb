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

import re as _re  # noqa: E402

_ALLOWED_TAGS = {
    "p", "br", "strong", "em", "b", "i", "a",
    "ul", "ol", "li", "blockquote", "code", "pre",
    # #1094 — médias embarqués (générés par _embed_media, jamais par l'auteur :
    # markdown-it a `html:False`, donc aucune balise brute ne vient du corps).
    "img", "video", "audio", "embed",
}
_ALLOWED_ATTRS = {
    "a": {"href", "title"},
    "img": {"src", "alt", "loading"},
    "video": {"src", "controls", "preload", "playsinline"},
    "audio": {"src", "controls", "preload"},
    "embed": {"src", "type"},
}
_LINK_REL = "nofollow ugc noopener noreferrer"

# Extensions par famille de média embarqué.
_MEDIA_IMG = {"png", "jpg", "jpeg", "webp", "gif", "avif"}
_MEDIA_VID = {"mp4", "webm", "ogv", "mov"}
_MEDIA_AUD = {"mp3", "ogg", "oga", "wav", "m4a", "weba", "aac", "flac"}

# Une référence média dans le corps : on n'en garde QUE le chemin
# `/media/<fichier>.<ext>` — jamais l'hôte, donc une réf pointant ailleurs
# devient billets-relative (aucune exfiltration possible). Le lookbehind évite
# de toucher une réf déjà dans un attribut (src="…"), le lookahead de la couper
# à l'intérieur d'une balise.
_MEDIA_REF = _re.compile(
    r"""(?<![\"'=])(?:https?://[^\s"'<>]+)?(/media/[A-Za-z0-9._~-]+\.([A-Za-z0-9]{2,5}))(?![^<]*>)"""
)


def _embed_media(html: str) -> str:
    """Transforme une réf `/media/x.ext` NUE en média embarqué selon son type
    (#1094) : image→<img>, vidéo→<video>, audio→<audio>, pdf→<embed>. Le reste
    est laissé tel quel."""
    def repl(m: "_re.Match") -> str:
        path, ext = m.group(1), m.group(2).lower()
        if ext in _MEDIA_IMG:
            return f'<img src="{path}" alt="" loading="lazy">'
        if ext in _MEDIA_VID:
            return f'<video src="{path}" controls preload="metadata" playsinline></video>'
        if ext in _MEDIA_AUD:
            return f'<audio src="{path}" controls preload="none"></audio>'
        if ext == "pdf":
            return f'<embed src="{path}" type="application/pdf">'
        return m.group(0)
    return _MEDIA_REF.sub(repl, html)


def render_markdown(text: str) -> str:
    """Render restricted markdown to sanitized HTML (safe to mark |safe in Jinja)."""
    html = _MD.render(text or "")
    html = _embed_media(html)
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
