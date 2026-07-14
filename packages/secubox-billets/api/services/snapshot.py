# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""
SecuBox-Deb :: billets embed snapshot
CyberMind — https://cybermind.fr

Capture a still "vignette" of a billet's embed for the communiqué poster look
and the portable offline archive.

Two sources, tried in order:
  1. a headless-Chromium full-page screenshot (real render), IF `playwright` is
     importable AND a browser binary is installed. This is OPTIONAL — enable it
     with `pip install playwright && playwright install chromium`. Any import
     error, launch failure, navigation timeout or exception falls through.
  2. the page's og:image (an https URL), fetched through the SAME SSRF policy as
     the rest of the module (host must resolve to a public unicast IP; https
     only; redirects re-validated; size-capped).

Whatever bytes come back are fed through `services.media.process` (full
re-encode → EXIF-strip + polyglot-neutralise, plus a bounded vignette) and
written with `services.media.store`. Returns (filename, thumb_filename) or None
if BOTH sources failed / produced nothing usable.

`capture()` is SYNCHRONOUS and does blocking IO + (optionally) drives a browser.
It MUST be run OFF the shared event loop (the caller uses `asyncio.to_thread`).
Never call it directly inside an async handler.
"""
from __future__ import annotations

import os
from pathlib import Path
from urllib.parse import urljoin

import httpx

from . import media
from . import ssrf

# Bounds for the whole capture. The browser goto/wait budget (~22s) keeps the
# to_thread worker from lingering; the og:image fetch is size- and time-capped.
GOTO_TIMEOUT_MS = 20000
SETTLE_MS = 2000
IMAGE_MAX_BYTES = media.MAX_BYTES          # 5 MiB, same ceiling as uploads
IMAGE_TIMEOUT = 10.0


def _browser_enabled(explicit: bool | None) -> bool:
    if explicit is not None:
        return explicit
    # Off by default only if the operator disables it; the import/launch guard
    # below makes "enabled but unavailable" degrade silently to og:image.
    return os.environ.get("BILLETS_SNAPSHOT_BROWSER", "1") != "0"


def _screenshot_via_browser(embed_url: str, resolver=ssrf._default_resolver) -> bytes | None:
    """Full-page PNG screenshot via headless Chromium, or None if unavailable.

    Guarded so a missing `playwright` package OR a missing browser binary OR any
    navigation error simply returns None (the caller then tries og:image)."""
    # SSRF: the browser path is as dangerous as any server-side fetch — an author
    # could point embed_url at an internal service (127.0.0.1, RFC1918, ::1,
    # 169.254.169.254). Validate the target resolves to a PUBLIC IP before we let
    # Chromium touch it; on rejection return None → the (also-guarded) og:image
    # fallback runs. (Residual: a *public* URL that server-redirects to an
    # internal host — mitigated by aborting non-public requests via the route below.)
    try:
        ssrf.validate_url(embed_url, resolver=resolver)
    except ssrf.SSRFError:
        return None
    try:
        from playwright.sync_api import sync_playwright
    except Exception:  # noqa: BLE001 — ImportError or a broken partial install
        return None

    def _guard(route):
        # Abort any request (redirect target, sub-resource) to a non-public host.
        try:
            ssrf.validate_url(route.request.url, resolver=resolver)
            route.continue_()
        except Exception:  # noqa: BLE001
            route.abort()

    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            try:
                page = browser.new_page()
                page.route("**/*", _guard)
                page.set_default_timeout(GOTO_TIMEOUT_MS)
                page.goto(embed_url, timeout=GOTO_TIMEOUT_MS, wait_until="networkidle")
                page.wait_for_timeout(SETTLE_MS)
                return page.screenshot(full_page=True)
            finally:
                browser.close()
    except Exception:  # noqa: BLE001 — never let a browser hiccup break a save
        return None


def _fetch_public_bytes(url: str, *, client: httpx.Client, resolver,
                        max_bytes: int = IMAGE_MAX_BYTES,
                        timeout: float = IMAGE_TIMEOUT) -> bytes:
    """SSRF-guarded synchronous GET (mirror of services.ssrf.fetch, sync).

    Validates https + all-public-IP before every hop, does not auto-follow
    redirects (each Location is re-validated), and caps the body. Raises
    ssrf.SSRFError on any policy violation."""
    current = url
    for _ in range(ssrf.MAX_REDIRECTS + 1):
        ssrf.validate_url(current, resolver=resolver)
        with client.stream("GET", current, follow_redirects=False,
                           timeout=timeout) as resp:
            if resp.status_code in (301, 302, 303, 307, 308):
                loc = resp.headers.get("location")
                if not loc:
                    raise ssrf.SSRFError("redirect without Location")
                current = urljoin(current, loc)
                continue
            body = b""
            for chunk in resp.iter_bytes():
                body += chunk
                if len(body) > max_bytes:
                    raise ssrf.SSRFError(f"response exceeds {max_bytes} bytes")
            return body
    raise ssrf.SSRFError("too many redirects")


def _og_image_bytes(og_image_url: str, *, client: httpx.Client | None, resolver) -> bytes | None:
    own_client = client is None
    c = client or httpx.Client(headers={"user-agent": "billets/0.1 (+secubox)"})
    try:
        return _fetch_public_bytes(og_image_url, client=c, resolver=resolver)
    except (ssrf.SSRFError, httpx.HTTPError, OSError):
        return None
    finally:
        if own_client:
            c.close()


def capture(embed_url: str, og_image_url: str | None, media_id: str, *,
            client: httpx.Client | None = None,
            resolver=ssrf._default_resolver,
            directory: Path | None = None,
            enable_browser: bool | None = None) -> tuple[str, str] | None:
    """Capture a vignette of `embed_url`; store it via services.media.

    Returns (filename, thumb_filename) on success, or None if neither the
    headless screenshot nor the og:image fallback yielded a usable image."""
    raw: bytes | None = None
    if _browser_enabled(enable_browser):
        raw = _screenshot_via_browser(embed_url, resolver=resolver)
    if raw is None and og_image_url:
        raw = _og_image_bytes(og_image_url, client=client, resolver=resolver)
    if not raw:
        return None
    try:
        processed = media.process(raw)
    except media.MediaError:
        return None
    return media.store(media_id, processed, directory)
