# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3597 — un module installé mais désactivé n'est ni au menu ni compté « à l'arrêt »."""
from api import main as hub

BRUT = """secubox-appstore.service disabled enabled
secubox-peertube.service disabled enabled
secubox-mqtt.service masked enabled
secubox-dns.service enabled enabled
secubox-waker.service disabled enabled
secubox-waker.socket enabled enabled
secubox-group@.service static -
"""


def test_desactives_et_masques_seulement():
    d = hub.unites_desactivees(BRUT)
    assert d == {"appstore", "peertube", "mqtt"}


def test_socket_active_garde_le_module():
    assert "waker" not in hub.unites_desactivees(BRUT)


def test_sortie_vide_ne_masque_rien():
    assert hub.unites_desactivees("") == set()


def _menu(monkeypatch, desactivees, actifs):
    items = [{"id": m, "name": m, "category": "services"} for m in ("appstore", "peertube", "dns")]
    monkeypatch.setattr(hub, "_load_menu_definitions", lambda: items)
    monkeypatch.setattr(hub, "_epingles_off", lambda: set())
    monkeypatch.setattr(hub, "_menu_off_du_profil", lambda: set())
    monkeypatch.setattr(hub, "_check_module_installed", lambda m: True)
    monkeypatch.setattr(hub, "_check_module_active", lambda m: m in actifs)
    monkeypatch.setattr(hub, "_unites_desactivees", lambda: desactivees)
    return hub._compute_menu_sync()


def _ids(menu):
    return {i["id"] for e in menu.get("espaces", []) for i in e["items"]}


def test_menu_retire_le_desactive_arrete(monkeypatch):
    assert _ids(_menu(monkeypatch, {"appstore", "peertube"}, {"dns"})) == {"dns"}


def test_desactive_mais_en_marche_reste(monkeypatch):
    assert "peertube" in _ids(_menu(monkeypatch, {"peertube"}, {"dns", "peertube"}))


def test_sans_releve_rien_ne_disparait(monkeypatch):
    assert _ids(_menu(monkeypatch, set(), set())) == {"appstore", "peertube", "dns"}
