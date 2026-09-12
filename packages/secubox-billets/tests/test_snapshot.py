# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""Embed snapshot capture: headless-Chromium path is OPTIONAL, so with the
browser simulated absent it must fall back to the SSRF-guarded og:image, and
must never fetch a private/non-public og:image."""
import io

import httpx
from PIL import Image

from api.services import snapshot


def _png_bytes(size=(320, 240)) -> bytes:
    buf = io.BytesIO()
    Image.new("RGB", size, (12, 74, 136)).save(buf, format="PNG")
    return buf.getvalue()


def _resolver(mapping=None):
    mapping = mapping or {}

    def r(host, port):
        return [(0, 0, 0, "", (mapping.get(host, "93.184.216.34"), port))]
    return r


def test_capture_falls_back_to_og_image(tmp_path, monkeypatch):
    # Simulate playwright absent / no browser binary → screenshot returns None.
    monkeypatch.setattr(snapshot, "_screenshot_via_browser", lambda url, **kw: None)
    png = _png_bytes()

    def handler(request):
        assert request.url.host == "cdn.example"
        return httpx.Response(200, content=png, headers={"content-type": "image/png"})

    client = httpx.Client(transport=httpx.MockTransport(handler))
    res = snapshot.capture(
        "https://site.example/post", "https://cdn.example/og.png",
        "01SNAP0000000000000000000A", client=client, resolver=_resolver(),
        directory=tmp_path, enable_browser=True)
    client.close()
    assert res is not None
    filename, thumb = res
    assert (tmp_path / filename).exists() and (tmp_path / thumb).exists()
    # stored file is a valid, re-encoded image (EXIF-stripped by media.process)
    Image.open(tmp_path / filename).verify()


def test_capture_returns_none_when_both_fail(tmp_path, monkeypatch):
    monkeypatch.setattr(snapshot, "_screenshot_via_browser", lambda url, **kw: None)

    def handler(request):
        return httpx.Response(200, content=b"not an image at all",
                              headers={"content-type": "text/plain"})

    client = httpx.Client(transport=httpx.MockTransport(handler))
    res = snapshot.capture(
        "https://site.example/post", "https://cdn.example/og.png",
        "01SNAP0000000000000000000B", client=client, resolver=_resolver(),
        directory=tmp_path, enable_browser=True)
    client.close()
    assert res is None
    assert list(tmp_path.iterdir()) == []


def test_capture_returns_none_without_og_and_no_browser(tmp_path, monkeypatch):
    monkeypatch.setattr(snapshot, "_screenshot_via_browser", lambda url, **kw: None)
    res = snapshot.capture(
        "https://site.example/post", None, "01SNAP0000000000000000000D",
        resolver=_resolver(), directory=tmp_path, enable_browser=True)
    assert res is None


def test_capture_ssrf_rejects_private_og(tmp_path, monkeypatch):
    monkeypatch.setattr(snapshot, "_screenshot_via_browser", lambda url, **kw: None)
    calls = {"n": 0}

    def handler(request):
        calls["n"] += 1
        return httpx.Response(200, content=_png_bytes(),
                              headers={"content-type": "image/png"})

    client = httpx.Client(transport=httpx.MockTransport(handler))
    res = snapshot.capture(
        "https://site.example/post", "https://intra.example/og.png",
        "01SNAP0000000000000000000C", client=client,
        resolver=_resolver({"intra.example": "10.0.0.5"}),
        directory=tmp_path, enable_browser=True)
    client.close()
    assert res is None
    assert calls["n"] == 0          # SSRF blocked BEFORE any network fetch
    assert list(tmp_path.iterdir()) == []


def test_browser_path_ssrf_rejects_internal_embed_url(monkeypatch):
    """The Chromium path must refuse an internal embed_url (SSRF) before launching."""
    from api.services import snapshot
    # resolver that maps the target to a private IP
    monkeypatch.setattr(snapshot.ssrf, "_default_resolver",
                        lambda host, port: [(0, 0, 0, "", ("127.0.0.1", port))])
    # if it were to proceed it would try to import/launch playwright; assert it returns None first
    out = snapshot._screenshot_via_browser("https://internal.example/",
                                           resolver=lambda h, p: [(0, 0, 0, "", ("10.0.0.5", p))])
    assert out is None


# ── Poster PeerTube souverain (#1268) ────────────────────────────────────────
def test_peertube_preview_souverain():
    """Embed PeerTube du parc → vignette via l'API PeerTube (2 GET : métadonnées
    puis image), sans navigateur ni og:image tiers."""
    seen = []

    def handler(request):
        seen.append(str(request.url))
        if request.url.path.endswith("/api/v1/videos/AbC123-xyz"):
            return httpx.Response(200, json={"previewPath": "/lazy-static/thumbnails/p.jpg",
                                             "thumbnailPath": "/x.jpg"})
        return httpx.Response(200, content=b"PREVIEW-JPEG-BYTES")

    c = httpx.Client(transport=httpx.MockTransport(handler))
    out = snapshot._peertube_preview_bytes(
        "https://peertube.gk2.secubox.in/videos/embed/AbC123-xyz", client=c)
    assert out == b"PREVIEW-JPEG-BYTES"
    assert seen[0].endswith("/api/v1/videos/AbC123-xyz")
    assert seen[1].endswith("/lazy-static/thumbnails/p.jpg")  # previewPath préféré


def test_peertube_preview_host_exact():
    """Seul l'hôte PeerTube configuré est accepté : un hôte tiers (même contenant
    'peertube') ou YouTube → None, sans aucun fetch."""
    def handler(request):
        raise AssertionError("ne doit pas fetch un hôte non autorisé")
    c = httpx.Client(transport=httpx.MockTransport(handler))
    assert snapshot._peertube_preview_bytes("https://peertube.evil.com/w/AbC123", client=c) is None
    assert snapshot._peertube_preview_bytes(
        "https://www.youtube.com/watch?v=dQw4w9WgXcQ", client=c) is None


def test_peertube_preview_swallows_errors():
    def handler(request):
        return httpx.Response(500)
    c = httpx.Client(transport=httpx.MockTransport(handler))
    assert snapshot._peertube_preview_bytes(
        "https://peertube.gk2.secubox.in/w/AbC123-xyz", client=c) is None


def test_youtube_thumb_fallback(monkeypatch):
    """maxres absent (petit placeholder) → bascule sur sddefault."""
    calls = []

    def fake(url, *, client, resolver):
        calls.append(url)
        if "maxresdefault" in url:
            return b"x" * 100          # < 1500 → ignoré (pixel gris de YouTube)
        return b"y" * 3000

    monkeypatch.setattr(snapshot, "_fetch_public_bytes", fake)
    out = snapshot._youtube_thumb_bytes(
        "https://www.youtube.com/watch?v=dQw4w9WgXcQ", client=object(), resolver=None)
    assert out == b"y" * 3000
    assert any("maxresdefault" in u for u in calls)
    assert any("sddefault" in u for u in calls)


def test_youtube_thumb_none_for_non_youtube(monkeypatch):
    monkeypatch.setattr(snapshot, "_fetch_public_bytes",
                        lambda *a, **k: (_ for _ in ()).throw(AssertionError("no fetch")))
    assert snapshot._youtube_thumb_bytes(
        "https://peertube.gk2.secubox.in/w/abc", client=None, resolver=None) is None
