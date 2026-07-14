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
    monkeypatch.setattr(snapshot, "_screenshot_via_browser", lambda url: None)
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
    monkeypatch.setattr(snapshot, "_screenshot_via_browser", lambda url: None)

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
    monkeypatch.setattr(snapshot, "_screenshot_via_browser", lambda url: None)
    res = snapshot.capture(
        "https://site.example/post", None, "01SNAP0000000000000000000D",
        resolver=_resolver(), directory=tmp_path, enable_browser=True)
    assert res is None


def test_capture_ssrf_rejects_private_og(tmp_path, monkeypatch):
    monkeypatch.setattr(snapshot, "_screenshot_via_browser", lambda url: None)
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
