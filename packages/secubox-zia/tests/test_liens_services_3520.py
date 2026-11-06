# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""Liens des services de ZIA : sbx:// sans doublon, url sur l'hôte admin (#3520)."""
import pytest

from api import bus


@pytest.mark.parametrize("sid,path,uri,url", [
    ("freebox", "/freebox/", "sbx://freebox/", "https://admin.exemple.test/freebox/"),
    ("p2p", "/p2p/", "sbx://p2p/", "https://admin.exemple.test/p2p/"),
    ("waf", "/waf/vue.html", "sbx://waf/vue.html", "https://admin.exemple.test/waf/vue.html"),
    ("media", "/smb/", "sbx://media/smb/", "https://admin.exemple.test/smb/"),
])
def test_adresses(monkeypatch, sid, path, uri, url):
    monkeypatch.setattr(bus, "_hote", lambda s: f"{s}.exemple.test")
    assert bus.adresses_service(sid, path) == (uri, url)


def test_sans_domaine_pas_de_fausse_url(monkeypatch):
    monkeypatch.setattr(bus, "_hote", lambda s: "")
    assert bus.adresses_service("freebox", "/freebox/") == ("sbx://freebox/", "")
