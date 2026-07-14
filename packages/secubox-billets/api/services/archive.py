# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""
SecuBox-Deb :: billets portable archive
CyberMind — https://cybermind.fr

Render a single, fully self-contained .html snapshot of a billet in the
communiqué layout — no external requests at all, so it opens offline forever:

  * all CSS is inlined; fonts are a system stack (no Google Fonts fetch);
  * every attached image and the embed vignette are inlined as `data:` base64
    URIs (bytes read off the event loop by the caller);
  * the embed is rendered as its snapshot image LINKING to the original
    embed_url (a live <iframe> cannot work offline);
  * the body is the same sanitized markdown render as the public page, and
    every dynamic value is HTML-escaped.

`render()` does blocking file IO (media reads); the caller runs it in a thread.
"""
from __future__ import annotations

import base64
from html import escape
from urllib.parse import urlparse

from . import media
from .feeds import billet_title
from .render import render_markdown

# System-font stack — deliberately no webfont so the file is truly offline.
_ARCHIVE_CSS = """
:root{--bg:#FFFFFF;--surf:#FAFAF8;--surf2:#F4F3EF;--border:#E2E0D8;
--text:#1A1A18;--muted:#6B6963;--auth:#C04E24;--wall:#9A6010;--boot:#803018;
--mind:#3D35A0;--root:#0A5840;--mesh:#104A88;
--sans:'Space Grotesk',ui-sans-serif,system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;
--mono:'JetBrains Mono',ui-monospace,'SFMono-Regular',Menlo,Consolas,'Liberation Mono',monospace}
*{margin:0;padding:0;box-sizing:border-box}
html,body{background:var(--surf);color:var(--text);font-family:var(--sans);
-webkit-font-smoothing:antialiased}
body{position:relative;min-height:100vh;padding-left:6px}
body::before{content:"";position:fixed;left:0;top:0;bottom:0;width:6px;
background:linear-gradient(180deg,var(--root),var(--mesh),var(--mind));z-index:10}
.wrap{max-width:720px;margin:0 auto;padding:48px 24px 64px}
.stamp{display:inline-block;border:2px solid var(--auth);color:var(--auth);
font-family:var(--mono);font-size:11px;font-weight:700;letter-spacing:.28em;
text-transform:uppercase;padding:6px 14px;transform:rotate(-2deg);margin-bottom:24px}
h1{font-size:clamp(28px,5.5vw,48px);font-weight:700;line-height:1.04;
letter-spacing:-.02em;text-transform:uppercase;margin-bottom:12px}
h1 .accent{color:var(--mind)}
.kicker{font-family:var(--mono);font-size:12px;color:var(--muted);
letter-spacing:.14em;text-transform:uppercase;margin-bottom:32px}
.kicker b{color:var(--root);font-weight:700}
.body{font-size:17px;line-height:1.6;margin-bottom:32px}
.body p{margin-bottom:14px}.body a{color:var(--mesh)}
.frame{background:var(--bg);border:1px solid var(--border);padding:14px;
position:relative;box-shadow:8px 8px 0 var(--surf2),8px 8px 0 1px var(--border);
margin-bottom:16px}
.frame::before{content:"TRANSMISSION · CANAL PUBLIC";position:absolute;top:-9px;
left:16px;background:var(--surf);padding:0 8px;font-family:var(--mono);
font-size:10px;letter-spacing:.2em;color:var(--mesh);font-weight:700}
.frame img{display:block;width:100%;height:auto;margin:0 auto;border:0}
.frame a{display:block}
.frame .noshot{font-family:var(--mono);font-size:13px;color:var(--mesh);
padding:24px 8px;text-align:center;word-break:break-all}
.gallery{display:flex;flex-wrap:wrap;gap:10px;margin-bottom:16px}
.gallery img{max-width:220px;height:auto;border:1px solid var(--border)}
.slogans{margin-top:40px;display:grid;gap:0;border-top:1px solid var(--border)}
.slogans p{font-family:var(--mono);font-size:12px;padding:12px 0;
border-bottom:1px solid var(--border);letter-spacing:.06em;color:var(--muted)}
.slogans p::before{content:"\\25B8 ";font-weight:700}
.slogans p:nth-child(1)::before{color:var(--auth)}
.slogans p:nth-child(2)::before{color:var(--wall)}
.slogans p:nth-child(3)::before{color:var(--boot)}
.slogans p:nth-child(4)::before{color:var(--mind)}
.slogans p:nth-child(5)::before{color:var(--root)}
.slogans p:nth-child(6)::before{color:var(--mesh)}
.slogans p strong{color:var(--text)}
footer{margin-top:32px;font-family:var(--mono);font-size:10px;color:var(--muted);
letter-spacing:.18em;text-transform:uppercase;display:flex;
justify-content:space-between;flex-wrap:wrap;gap:8px}
@media (max-width:560px){.wrap{padding:32px 14px 48px}}
""".strip()

_SLOGANS = [
    ("AUTH", "l'identité ne se délègue pas."),
    ("WALL", "la défense agit hors du chemin."),
    ("BOOT", "la confiance commence au démarrage."),
    ("MIND", "l'appareil observe, l'humain décide."),
    ("ROOT", "le socle est disclosed, jamais dilué."),
    ("MESH", "chaque nœud tient la ligne."),
]


def _data_uri(mime: str, raw: bytes) -> str:
    return f"data:{mime};base64,{base64.b64encode(raw).decode('ascii')}"


def _embed_block(billet: dict) -> str:
    """The poster frame: the embed snapshot inlined as a data: image, linking to
    the original embed_url. Falls back to a plain link when there is no snapshot."""
    embed_url = billet.get("embed_url")
    snap = billet.get("embed_snapshot")
    inner = ""
    if snap:
        try:
            raw = media.read_bytes(snap)
            mime = "image/png" if snap.lower().endswith((".png", ".gif")) else "image/jpeg"
            if snap.lower().endswith(".webp"):
                mime = "image/webp"
            img = f'<img src="{_data_uri(mime, raw)}" alt="Aperçu de la transmission">'
            inner = (f'<a href="{escape(embed_url, quote=True)}" rel="noopener nofollow ugc">{img}</a>'
                     if embed_url else img)
        except OSError:
            inner = ""
    if not inner:
        if not embed_url:
            return ""
        inner = (f'<a class="noshot" href="{escape(embed_url, quote=True)}" '
                 f'rel="noopener nofollow ugc">{escape(embed_url)}</a>')
    return f'<div class="frame">{inner}</div>'


def _gallery_block(media_items: list[dict]) -> str:
    imgs = []
    for m in media_items:
        try:
            raw = media.read_bytes(m["filename"])
        except OSError:
            continue
        imgs.append(f'<img src="{_data_uri(m.get("mime") or "image/png", raw)}" '
                    f'alt="{escape(m.get("alt") or "")}">')
    return f'<div class="gallery">{"".join(imgs)}</div>' if imgs else ""


def render(billet: dict, media_items: list[dict]) -> str:
    """Build the self-contained communiqué HTML string for one billet.

    Blocking (reads media files); run it in a thread from an async handler."""
    title = billet_title(billet.get("body") or "")
    body_html = render_markdown(billet.get("body") or "")
    published = (billet.get("published_at") or billet.get("updated_at") or "")[:19].replace("T", " ")
    host = urlparse(billet.get("embed_url") or "").hostname or ""
    slogans = "".join(f"<p><strong>{escape(k)}</strong> — {escape(v)}</p>" for k, v in _SLOGANS)
    return (
        "<!DOCTYPE html>\n"
        '<html lang="fr"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width, initial-scale=1">'
        f"<title>{escape(title)} · Communiqué</title>"
        f"<style>{_ARCHIVE_CSS}</style></head><body><div class=\"wrap\">"
        '<div class="stamp">Communiqué officiel</div>'
        f"<h1>{escape(title)}</h1>"
        '<p class="kicker">CYBERMIND · SECUBOX-DEB · '
        "<b>SOUVERAINETÉ PAR CONSTRUCTION</b></p>"
        f'<div class="body">{body_html}</div>'
        + _embed_block(billet)
        + _gallery_block(media_items)
        + f'<div class="slogans">{slogans}</div>'
        + '<footer><span>CYBERMIND — NOTRE-DAME-DU-CRUET · SAVOIE</span>'
        + f"<span>{escape(published)} · {escape(host)}</span></footer>"
        + "</div></body></html>"
    )
