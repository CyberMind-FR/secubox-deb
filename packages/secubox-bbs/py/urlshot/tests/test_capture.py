# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""Tests de l'orchestrateur de capture og:image -> repli screenshot (#1120).

Duck-typé de bout en bout : `ogimage.cherche_og_image` et
`shotter.capture` sont remplacés par des doublures — aucun réseau, aucun
chromium réel n'est jamais sollicité."""
import capture


class _DummyClient:
    """Double du client d'égress : juste assez pour `.close()`."""

    def close(self):
        pass


def _patch_egress_client(monkeypatch):
    """Neutralise `egress.client()` : ce test ne veut dépendre ni d'httpx
    (`Recommends` Debian, pas une dépendance dure) ni du réseau."""
    monkeypatch.setattr(capture.egress, "client", lambda: _DummyClient())


def _patch_url_autorisee(monkeypatch):
    """Neutralise `egress.url_interdite()` pour une URL "autorisée" fictive :
    la vraie implémentation résout le DNS, ce que ces tests d'orchestration
    (déjà couverte séparément par tests/test_egress.py) ne veulent pas
    dépendre du réseau du bac à sable."""
    monkeypatch.setattr(capture.egress, "url_interdite", lambda url: None)


def test_og_image_trouvee_court_circuite_le_repli_screenshot(monkeypatch):
    _patch_egress_client(monkeypatch)
    _patch_url_autorisee(monkeypatch)
    monkeypatch.setattr(capture.ogimage, "cherche_og_image", lambda url, cli: b"IMG")

    def _shotter_jamais_appele(*args, **kwargs):
        raise AssertionError("le repli screenshot ne doit pas être sollicité")

    monkeypatch.setattr(capture.shotter, "capture", _shotter_jamais_appele)

    assert capture.capture_vignette("https://ok.example/") == (b"IMG", True)


def test_repli_screenshot_si_pas_dog_image(monkeypatch):
    _patch_egress_client(monkeypatch)
    _patch_url_autorisee(monkeypatch)
    monkeypatch.setattr(capture.ogimage, "cherche_og_image", lambda url, cli: None)

    async def _fake_shotter_capture(url, *, wait=None, proxy=None, ca=None, **kwargs):
        assert proxy == capture._PROXY_URL
        assert ca == capture._CA_PATH
        assert wait is capture.shotter.wait_static_ready
        return b"SHOT"

    monkeypatch.setattr(capture.shotter, "capture", _fake_shotter_capture)

    assert capture.capture_vignette("https://ok.example/") == (b"SHOT", True)


def test_les_deux_voies_en_echec_renvoient_none_false(monkeypatch):
    _patch_egress_client(monkeypatch)
    _patch_url_autorisee(monkeypatch)

    def _og_leve(url, cli):
        raise RuntimeError("panne réseau simulée")

    async def _shotter_leve(url, *, wait=None, proxy=None, ca=None, **kwargs):
        raise capture.shotter.ShotError("chromium indisponible")

    monkeypatch.setattr(capture.ogimage, "cherche_og_image", _og_leve)
    monkeypatch.setattr(capture.shotter, "capture", _shotter_leve)

    assert capture.capture_vignette("https://ok.example/") == (None, False)


def test_ssrf_refuse_avant_tout_fetch(monkeypatch):
    def _jamais_appele(*args, **kwargs):
        raise AssertionError("aucun fetch ne doit avoir lieu pour une URL SSRF")

    monkeypatch.setattr(capture.egress, "client", _jamais_appele)
    monkeypatch.setattr(capture.ogimage, "cherche_og_image", _jamais_appele)

    async def _shotter_jamais_appele(*args, **kwargs):
        raise AssertionError("le repli screenshot ne doit pas être sollicité")

    monkeypatch.setattr(capture.shotter, "capture", _shotter_jamais_appele)

    assert capture.capture_vignette("http://127.0.0.1/") == (None, False)
