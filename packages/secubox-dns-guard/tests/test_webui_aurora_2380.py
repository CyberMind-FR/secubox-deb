# SPDX-License-Identifier: LicenseRef-CMSD-1.0
"""Webui DNS Guard au profil Aurora (#2380) : contrôles statiques, sans navigateur."""
import re
from pathlib import Path

PAGE = Path(__file__).resolve().parents[1] / "www" / "dns-guard" / "index.html"
SRC = PAGE.read_text(encoding="utf-8")


def test_spdx_et_licence():
    assert "SPDX-License-Identifier: LicenseRef-CMSD-1.0" in SRC[:400]


def test_hauteur_demo_embed():
    assert "sbxVue" in SRC and "onglet:'dns-guard'" in SRC
    assert "demo" in SRC and "embed" in SRC and "DÉMONSTRATION" in SRC
    assert "min-height:100vh" not in SRC and "scrollHeight" not in SRC


def test_aucune_dependance_externe():
    for m in re.findall(r"<script[^>]*\ssrc=[\"']([^\"']+)", SRC):
        assert not re.match(r"(https?:)?//", m)
    assert "<script src=" not in SRC                                                   # le menu latéral est injecté, jamais une balise externe
    assert not re.search(r"https?://(?!www\.w3\.org)", re.sub(r"<!--.*?-->", "", SRC, flags=re.S))


def test_ni_lorem_ni_secret_ni_boite_navigateur():
    bas = SRC.lower()
    assert "lorem" not in bas
    assert not re.search(r"(password|passwd|secret|api[_-]?key)\s*[:=]", bas)
    assert not re.search(r"\b(confirm|alert|prompt)\(", SRC)


def test_routes_citees_et_ecritures_identiques():
    assert "/api/v1/dns-guard" in SRC
    for r in ("/status", "/alerts", "/top-blocked", "/stats", "/check/", "/sinkhole/status", "/sinkhole/sources", "/sinkhole/whitelist",
              "/sinkhole/ip-allowlist"):
        assert r in SRC
    # écritures de l'ancienne page, à l'identique
    for r in ("'/whitelist?domain='", "'/sinkhole/sync'", "'/sinkhole/disable'", "'/sinkhole/enable'", "'/sinkhole/sources/'", "?enabled=",
              "'/sinkhole/whitelist?domain='", "'/sinkhole/whitelist/'", "'/sinkhole/ip-allowlist?ip='", "'/sinkhole/ip-allowlist/'"):
        assert r in SRC, r
    assert "'POST'" in SRC and "'DELETE'" in SRC
    assert "localStorage.getItem('sbx_token')" in SRC and "'Content-Type':'application/json'" in SRC


def test_confirmation_integree_et_tiret():
    assert "confOui" in SRC and "confNon" in SRC
    assert "'—'" in SRC
