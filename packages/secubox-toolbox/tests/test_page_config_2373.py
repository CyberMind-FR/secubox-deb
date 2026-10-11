# SPDX-License-Identifier: LicenseRef-CMSD-1.0
"""Onglet Config du Toolbox au profil Aurora (#2373) : contrôles statiques de la page."""
import re
from pathlib import Path

PAGE = Path(__file__).resolve().parent.parent / "www" / "toolbox" / "config.html"


def _src() -> str:
    return PAGE.read_text(encoding="utf-8")


def test_spdx_et_nom():
    s = _src()
    assert "SPDX-License-Identifier: LicenseRef-CMSD-1.0" in s
    assert "onglet:'config'" in s


def test_protocole_cadre_et_demo():
    s = _src()
    assert "sbxToolboxVue" in s
    assert "ResizeObserver" in s
    assert "demo" in s and "DONNÉES DE DÉMONSTRATION" in s
    assert "embed" in s
    assert "min-height:100vh" not in s


def test_aucune_ressource_externe():
    s = _src()
    assert not re.search(r"<script[^>]+src=", s, re.I)
    assert not re.search(r"https?://(?!www\.w3\.org)", s.replace("https?://", ""))


def test_pas_de_dialogue_natif_ni_lorem():
    s = _src()
    for banni in ("confirm(", "alert(", "prompt(", "lorem"):
        assert banni not in s.lower() if banni == "lorem" else banni not in s


def test_aucun_secret_affiche():
    s = _src()
    assert "ca_key" not in s
    assert "key.pem" not in s
    assert "mac_salt" not in s
    assert "PRIVATE KEY" not in s


def test_routes_lues():
    s = _src()
    assert "/api/v1/toolbox" in s
    for r in ("/admin/config", "/health", "/rlevel/peers", "/ca/fingerprint",
              "/ca/android.crt", "/ca/android.der", "/ca/mobileconfig"):
        assert r in s, r


def test_lecture_seule_comme_l_ancien_onglet():
    """L'ancien onglet n'avait aucune écriture : la page n'en émet aucune."""
    s = _src()
    assert not re.search(r"method\s*:\s*['\"](POST|PUT|DELETE|PATCH)", s, re.I)
    assert "Authorization" in s and "sbx_token" in s
