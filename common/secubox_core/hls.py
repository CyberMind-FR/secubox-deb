# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: HLS media-playlist parser + segment-URI rewriter

Phase 2 (media-buffer reassembly) uses a **read-time join**: sbxmitm never
tracks HLS session state, it just captures the manifest and each segment
independently (tagged `kind="manifest"`/`kind="segment"`). At replay time
the DPI backend parses the captured manifest bytes with this module,
resolves every segment URI against the manifest's own URL, and looks the
resulting absolute URL up against the captured segment records to rewrite
the playlist to point at `/api/v1/dpi/media/replay/{seg_id}`.

Scope — **HLS media (single-variant) playlists only**:
- Master/multivariant (ABR) playlists (`#EXT-X-STREAM-INF`) and encrypted
  media (`#EXT-X-KEY` with METHOD != NONE) are detected via
  `is_master_playlist`/`is_encrypted` and marked unsupported by the caller —
  this module does not attempt to parse variants or decrypt segments.
- DASH `.mpd` manifests are out of scope entirely (not HLS `#EXTM3U`).

Canonicalization (must match the Go capture side — see mediabuffer.go /
main.go where a captured segment's `url` metatag field is always built as
`"https://" + host + req.URL.RequestURI()`, i.e. scheme forced to `https`,
host + path + query, exactly as observed on the wire):

    `resolve(base_url, uri)` = `urllib.parse.urljoin(base_url, uri)`, and if
    the result is an absolute `http://` URL, the scheme is rewritten to
    `https://` before returning. Path and query are left exactly as urljoin
    produces them (query is never stripped). This is the ONE canonical form
    used on both sides of the join; `rewrite()` builds its lookup key the
    same way, so a `mapping` built from segment records' stored `url`
    values (already `https://...`) matches directly.

Pure stdlib only (`re`, `urllib.parse`) — no FastAPI, no I/O. Fail-safe:
malformed/empty/non-string input never raises; functions degrade to their
empty/unsupported-shaped return value instead.
"""
from __future__ import annotations

import re
from urllib.parse import urljoin, urlsplit, urlunsplit

_STREAM_INF_RE = re.compile(r"^#EXT-X-STREAM-INF\b", re.IGNORECASE)
_KEY_RE = re.compile(r"^#EXT-X-KEY:(.*)$", re.IGNORECASE)
_METHOD_RE = re.compile(r"METHOD=([^,\s]+)", re.IGNORECASE)
_MAP_RE = re.compile(r'^#EXT-X-MAP:(.*)$', re.IGNORECASE)
_MAP_URI_RE = re.compile(r'URI="([^"]*)"', re.IGNORECASE)

DEFAULT_MAX_SEGMENTS = 5000


def _lines(text: str) -> list[str]:
    """Split playlist text into lines, fail-safe on non-string input."""
    if not isinstance(text, str) or not text:
        return []
    return text.splitlines()


def is_master_playlist(text: str) -> bool:
    """True if the playlist is a multivariant/ABR master playlist.

    Detected by the presence of an `#EXT-X-STREAM-INF` tag. Fail-safe:
    never raises, returns False on malformed/empty/non-string input.
    """
    try:
        for line in _lines(text):
            if _STREAM_INF_RE.match(line.strip()):
                return True
    except Exception:
        return False
    return False


def is_encrypted(text: str) -> bool:
    """True if any `#EXT-X-KEY` tag has a METHOD other than NONE.

    Fail-safe: never raises, returns False on malformed/empty/non-string
    input or when no `#EXT-X-KEY` tag is present.
    """
    try:
        for line in _lines(text):
            m = _KEY_RE.match(line.strip())
            if not m:
                continue
            method_m = _METHOD_RE.search(m.group(1))
            if method_m and method_m.group(1).strip().upper() != "NONE":
                return True
    except Exception:
        return False
    return False


def segment_uris(text: str) -> list[str]:
    """Ordered list of media segment URIs in a media playlist.

    Includes the `#EXT-X-MAP:URI="..."` init-segment URI first (if present),
    followed by every non-blank, non-`#`-prefixed line (the `#EXTINF`
    segment URIs) in order. All other `#`-tag lines are ignored.

    Fail-safe: never raises; returns `[]` on malformed/empty/non-string
    input.
    """
    out: list[str] = []
    try:
        lines = _lines(text)
        # Init segment (if any) is logically "first" regardless of where
        # the #EXT-X-MAP tag sits relative to #EXTINF lines.
        for line in lines:
            stripped = line.strip()
            m = _MAP_RE.match(stripped)
            if m:
                uri_m = _MAP_URI_RE.search(m.group(1))
                if uri_m:
                    out.append(uri_m.group(1))
                break  # only one init segment is meaningful
        for line in lines:
            stripped = line.strip()
            if not stripped:
                continue
            if stripped.startswith("#"):
                continue
            out.append(stripped)
    except Exception:
        return []
    return out


def resolve(base_url: str, uri: str) -> str:
    """Resolve a segment URI to an absolute URL against the manifest's URL.

    Uses `urllib.parse.urljoin`, then normalizes an absolute `http://`
    result to `https://` — the canonical form the Go capture side always
    stores (`"https://" + host + req.URL.RequestURI()`). Path and query are
    kept exactly as urljoin produces them.

    Fail-safe: never raises; returns `""` on malformed/non-string input.
    """
    try:
        if not isinstance(base_url, str) or not isinstance(uri, str):
            return ""
        absolute = urljoin(base_url, uri)
        parts = urlsplit(absolute)
        if parts.scheme == "http":
            parts = parts._replace(scheme="https")
            absolute = urlunsplit(parts)
        return absolute
    except Exception:
        return ""


def rewrite(text: str, mapping: dict[str, str], base_url: str,
            max_segments: int = DEFAULT_MAX_SEGMENTS) -> tuple[str, int, int]:
    """Rewrite segment URIs in a media playlist per `mapping`.

    For each segment URI (the `#EXT-X-MAP` init URI and every `#EXTINF`
    segment line, in order, up to `max_segments`), resolves it against
    `base_url` and replaces it with `mapping[abs_url]` when present. Only
    the URI token is replaced — the quoted value for `#EXT-X-MAP`, the
    whole line for a bare segment URI. Unmatched URIs are left unchanged.

    Returns `(rewritten_text, matched, total)` where `total` is the number
    of segment URIs seen (capped at `max_segments`) and `matched` is how
    many were found in `mapping`.

    Fail-safe: never raises; returns `(text or "", 0, 0)` on malformed
    input.
    """
    try:
        if not isinstance(text, str) or not text:
            return (text if isinstance(text, str) else "", 0, 0)
        if not isinstance(mapping, dict):
            mapping = {}
        lines = text.splitlines(keepends=True)
        out_lines: list[str] = []
        matched = 0
        total = 0
        map_seen = False
        for line in lines:
            stripped = line.strip()

            map_m = _MAP_RE.match(stripped) if not map_seen else None
            if map_m:
                map_seen = True
                if total >= max_segments:
                    out_lines.append(line)
                    continue
                uri_m = _MAP_URI_RE.search(map_m.group(1))
                if uri_m:
                    total += 1
                    uri = uri_m.group(1)
                    abs_url = resolve(base_url, uri)
                    if abs_url in mapping:
                        matched += 1
                        # Replace only the quoted value inside the line
                        # (locate the exact quoted token, not regex offsets
                        # relative to the group(1) substring).
                        quoted = f'"{uri}"'
                        idx = line.find(quoted)
                        if idx >= 0:
                            value_start = idx + 1
                            value_end = idx + len(quoted) - 1
                            new_line = line[:value_start] + mapping[abs_url] + line[value_end:]
                            out_lines.append(new_line)
                            continue
                out_lines.append(line)
                continue

            if stripped and not stripped.startswith("#"):
                if total >= max_segments:
                    out_lines.append(line)
                    continue
                total += 1
                abs_url = resolve(base_url, stripped)
                if abs_url in mapping:
                    matched += 1
                    # Preserve original line ending / surrounding whitespace
                    # by replacing just the URI token within the line.
                    idx = line.find(stripped)
                    if idx >= 0:
                        new_line = line[:idx] + mapping[abs_url] + line[idx + len(stripped):]
                    else:
                        new_line = mapping[abs_url] + "\n"
                    out_lines.append(new_line)
                    continue
                out_lines.append(line)
                continue

            out_lines.append(line)

        return ("".join(out_lines), matched, total)
    except Exception:
        return (text if isinstance(text, str) else "", 0, 0)
