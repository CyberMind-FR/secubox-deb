# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""Tests de l'extraction og:image pour urlshot (#1120)."""
import ogimage

PAGE_URL = "https://example.com/article"
IMG_BYTES = b"\xff\xd8\xff\xe0JFIFfake-jpeg-bytes"


class FakeResponse:
    def __init__(self, status_code=200, headers=None, content=b"", text=""):
        self.status_code = status_code
        self.headers = headers or {}
        self.content = content
        self.text = text if text else content.decode("utf-8", errors="replace")


class FakeClient:
    """Client factice keyed par URL exacte — n'a besoin que de .get()."""

    def __init__(self, routes):
        self.routes = routes
        self.appels = []

    def get(self, url):
        self.appels.append(url)
        if url not in self.routes:
            return FakeResponse(status_code=404)
        return self.routes[url]


def _html_response(body: str) -> FakeResponse:
    return FakeResponse(
        status_code=200,
        headers={"content-type": "text/html; charset=utf-8"},
        text=body,
    )


def test_og_image_absolue_recuperee():
    html = (
        "<html><head>"
        '<meta property="og:image" content="https://example.org/pic.jpg">'
        "</head><body></body></html>"
    )
    cli = FakeClient(
        {
            PAGE_URL: _html_response(html),
            "https://example.org/pic.jpg": FakeResponse(
                status_code=200,
                headers={"content-type": "image/jpeg"},
                content=IMG_BYTES,
            ),
        }
    )
    assert ogimage.cherche_og_image(PAGE_URL, cli) == IMG_BYTES


def test_sans_og_image_ni_twitter_image_renvoie_none():
    html = "<html><head><title>Rien ici</title></head><body></body></html>"
    cli = FakeClient({PAGE_URL: _html_response(html)})
    assert ogimage.cherche_og_image(PAGE_URL, cli) is None


def test_fallback_twitter_image():
    html = (
        "<html><head>"
        '<meta name="twitter:image" content="https://example.org/tw.png">'
        "</head><body></body></html>"
    )
    cli = FakeClient(
        {
            PAGE_URL: _html_response(html),
            "https://example.org/tw.png": FakeResponse(
                status_code=200,
                headers={"content-type": "image/png"},
                content=IMG_BYTES,
            ),
        }
    )
    assert ogimage.cherche_og_image(PAGE_URL, cli) == IMG_BYTES


def test_og_image_ssrf_interne_refusee_et_jamais_fetchee():
    html = (
        "<html><head>"
        '<meta property="og:image" content="http://127.0.0.1/x.png">'
        "</head><body></body></html>"
    )
    cli = FakeClient({PAGE_URL: _html_response(html)})
    assert ogimage.cherche_og_image(PAGE_URL, cli) is None
    assert "http://127.0.0.1/x.png" not in cli.appels


def test_og_image_relative_resolue_contre_origine_page():
    html = (
        "<html><head>"
        '<meta property="og:image" content="/pic.jpg">'
        "</head><body></body></html>"
    )
    cli = FakeClient(
        {
            PAGE_URL: _html_response(html),
            "https://example.com/pic.jpg": FakeResponse(
                status_code=200,
                headers={"content-type": "image/jpeg"},
                content=IMG_BYTES,
            ),
        }
    )
    assert ogimage.cherche_og_image(PAGE_URL, cli) == IMG_BYTES


def test_page_url_interdite_jamais_fetchee():
    cli = FakeClient({})
    assert ogimage.cherche_og_image("http://127.0.0.1/", cli) is None
    assert cli.appels == []


def test_page_non_html_renvoie_none():
    cli = FakeClient(
        {
            PAGE_URL: FakeResponse(
                status_code=200,
                headers={"content-type": "application/json"},
                text='{"foo": "bar"}',
            )
        }
    )
    assert ogimage.cherche_og_image(PAGE_URL, cli) is None


def test_page_non_2xx_renvoie_none():
    cli = FakeClient({PAGE_URL: FakeResponse(status_code=404, text="not found")})
    assert ogimage.cherche_og_image(PAGE_URL, cli) is None


def test_image_content_type_non_image_refusee():
    html = (
        "<html><head>"
        '<meta property="og:image" content="https://example.org/pic.jpg">'
        "</head><body></body></html>"
    )
    cli = FakeClient(
        {
            PAGE_URL: _html_response(html),
            "https://example.org/pic.jpg": FakeResponse(
                status_code=200,
                headers={"content-type": "text/html"},
                content=IMG_BYTES,
            ),
        }
    )
    assert ogimage.cherche_og_image(PAGE_URL, cli) is None
