# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""Feed + metadata builders (pure, testable).

Billets have no title field; `billet_title` derives one from the first line of
the body and `excerpt` a plain-text summary — both used for Atom/JSON feeds and
for OpenGraph / Twitter cards (the gateway's "look good when shared" half)."""
from __future__ import annotations

import re
from xml.sax.saxutils import escape as _xesc

_MD_STRIP = re.compile(r"[*_`>#\[\]]")
_LINK_TARGET = re.compile(r"\((https?://[^)]+)\)")


def billet_title(body: str, *, max_len: int = 70) -> str:
    line = next((ln.strip() for ln in (body or "").splitlines() if ln.strip()), "")
    line = _LINK_TARGET.sub("", _MD_STRIP.sub("", line)).strip()
    if not line:
        return "billet"
    return (line[: max_len - 1].rstrip() + "…") if len(line) > max_len else line


def excerpt(body: str, *, max_len: int = 200) -> str:
    text = _MD_STRIP.sub("", body or "")
    text = _LINK_TARGET.sub("", text)
    text = re.sub(r"\s+", " ", text).strip()
    return (text[: max_len - 1].rstrip() + "…") if len(text) > max_len else text


def build_atom(*, site_title: str, base_url: str, self_url: str,
               entries: list[dict], updated: str) -> str:
    """entries: {title, url, id, updated, published, content_html}."""
    out = ['<?xml version="1.0" encoding="utf-8"?>',
           '<feed xmlns="http://www.w3.org/2005/Atom">',
           f"<title>{_xesc(site_title)}</title>",
           f'<link href="{_xesc(base_url)}/"/>',
           f'<link rel="self" href="{_xesc(self_url)}"/>',
           f"<id>{_xesc(base_url)}/</id>",
           f"<updated>{_xesc(updated)}</updated>"]
    for e in entries:
        out += ["<entry>",
                f"<title>{_xesc(e['title'])}</title>",
                f'<link href="{_xesc(e["url"])}"/>',
                f"<id>{_xesc(e['id'])}</id>",
                f"<updated>{_xesc(e['updated'])}</updated>",
                f"<published>{_xesc(e['published'])}</published>",
                f'<content type="html">{_xesc(e["content_html"])}</content>',
                "</entry>"]
    out.append("</feed>")
    return "\n".join(out)


def build_jsonfeed(*, site_title: str, base_url: str, feed_url: str,
                   items: list[dict]) -> dict:
    """items: {id, url, title, content_html, date_published}, plus optional
    `summary` (short excerpt) and `tags` [{slug, emoji}].

    `summary` and `tags` are JSON Feed 1.1 standard fields, so generic readers
    understand them; the emoji has no standard home, so it rides in the
    `_secubox` extension (the spec reserves `_`-prefixed keys for exactly this).
    Optional keys are OMITTED rather than emitted as null — the spec asks for
    absence, and a null `summary` would render as the string "null" in naive
    readers.
    """
    out_items = []
    for it in items:
        entry = {"id": it["id"], "url": it["url"], "title": it["title"],
                 "content_html": it["content_html"],
                 "date_published": it["date_published"]}
        if it.get("summary"):
            entry["summary"] = it["summary"]
        tags = it.get("tags") or []
        if tags:
            entry["tags"] = [t["slug"] for t in tags]          # spec: array of strings
            entry["_secubox"] = {"tags": tags}                 # spec-legal extension: slug + emoji
        out_items.append(entry)
    return {
        "version": "https://jsonfeed.org/version/1.1",
        "title": site_title,
        "home_page_url": f"{base_url}/",
        "feed_url": feed_url,
        "items": out_items,
    }
