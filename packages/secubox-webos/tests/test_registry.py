# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""SecuBox-Deb :: WebOS — normalize_services (api.registry)."""
from api.registry import normalize_services, HEALTH_MAP, load_menu_cache, load_exposure_cache

MENU = {"categories": [{"items": [
    {"id": "waf", "name": "WAF", "category": "wall", "icon": "🔥", "path": "/waf/",
     "description": "", "installed": True, "active": True,
     "domain": "waf.gk2.secubox.in"},
    {"id": "radio", "name": "Radio", "category": "mind", "icon": "🎧", "path": "/radio/",
     "installed": True, "active": True, "same_origin": True},
]}]}
HEALTH = {"waf": {"status": "ok", "msg": "Running"},
          "radio": {"status": "error", "msg": "Failed"}}
EXPO = {"waf.gk2.secubox.in": {"reach": "wan", "latency_ms": 12.5}}


def test_health_mapping_and_join():
    svcs = {s.id: s for s in normalize_services(MENU, HEALTH, EXPO)}
    assert svcs["waf"].health.state == "online"
    assert svcs["waf"].urls.lan == "https://waf.gk2.secubox.in"
    assert svcs["waf"].urls.wan == "https://waf.gk2.secubox.in"   # reach=wan
    assert svcs["waf"].routing.mode == "wan"
    assert svcs["waf"].health.latency_ms == 12.5
    # radio: offline, same-origin (pas d'URL), latence absente
    assert svcs["radio"].health.state == "offline"
    assert svcs["radio"].urls.lan is None
    assert svcs["radio"].urls.wan is None
    assert svcs["radio"].health.latency_ms is None
    assert svcs["radio"].routing.available is False   # offline


def test_unknown_when_health_absent():
    svcs = {s.id: s for s in normalize_services(MENU, {}, None)}
    assert svcs["waf"].health.state == "unknown"
    assert svcs["waf"].urls.wan is None               # pas d'expo ⇒ pas de wan


def test_reach_lan_sets_lan_not_wan():
    """Anti-fuite : reach="lan" doit renseigner urls.lan mais JAMAIS urls.wan."""
    menu = {"categories": [{"items": [
        {"id": "svc", "name": "Svc", "category": "root", "domain": "svc.gk2.secubox.in"},
    ]}]}
    expo = {"svc.gk2.secubox.in": {"reach": "lan", "latency_ms": 3.0}}
    svcs = {s.id: s for s in normalize_services(menu, {}, expo)}
    assert svcs["svc"].urls.lan == "https://svc.gk2.secubox.in"
    assert svcs["svc"].urls.wan is None
    assert svcs["svc"].routing.mode == "lan"


def test_bare_item_normalizes_without_keyerror():
    """Un item avec seulement id+category (toutes les clés optionnelles
    absentes) doit se normaliser avec des valeurs par défaut sensées."""
    menu = {"categories": [{"items": [{"id": "x", "category": "root"}]}]}
    svcs = normalize_services(menu, {}, {})
    assert len(svcs) == 1
    s = svcs[0]
    assert s.id == "x"
    assert s.name == "x"
    assert s.category == "root"
    assert s.icon == ""
    # id-based convention fallback (api.idmap.resolve) still produces a lan URL,
    # but never a wan URL absent a matching exposure record.
    assert s.urls.lan == "https://x.gk2.secubox.in"
    assert s.urls.wan is None
    assert s.health.state == "unknown"
    assert s.installed is True
    assert s.active is True


def test_empty_menu_categories_yields_empty_list():
    assert normalize_services({"categories": []}, {}, {}) == []


def test_empty_menu_dict_yields_empty_list():
    assert normalize_services({}, {}, {}) == []


def test_load_menu_cache_missing_file_defaults():
    assert load_menu_cache("/nonexistent/menu.json") == {"categories": []}


def test_load_exposure_cache_missing_file_defaults():
    assert load_exposure_cache("/nonexistent/exposure.json") == {}


# #1175 santé socket-aware : ~110 modules servis in-process par l'agrégateur ont
# une unité systemd inactive/dead mais répondent via leur socket. La socket prime.
_MENU_SOCK = {"categories": [{"items": [
    {"id": "dpi", "name": "DPI", "category": "wall", "icon": "🔬",
     "path": "/dpi/", "installed": True, "active": True},
    {"id": "auth", "name": "Auth", "category": "auth", "icon": "🔑",
     "path": "/auth/", "installed": True, "active": True},
]}]}

def test_socket_promotes_inactive_to_online():
    # dpi: unité inactive → "warn" (degraded) MAIS socket présente ⇒ online
    health = {"dpi": {"status": "warn", "msg": "inactive/dead"}}
    svcs = {s.id: s for s in normalize_services(_MENU_SOCK, health, None,
                                                sockets=frozenset({"dpi"}))}
    assert svcs["dpi"].health.state == "online"

def test_socket_does_not_mask_failed():
    # auth: unité failed → "error" ; une socket périmée ne doit PAS le masquer
    health = {"auth": {"status": "error", "msg": "Failed"}}
    svcs = {s.id: s for s in normalize_services(_MENU_SOCK, health, None,
                                                sockets=frozenset({"auth"}))}
    assert svcs["auth"].health.state == "offline"

def test_no_socket_keeps_degraded():
    health = {"dpi": {"status": "warn", "msg": "inactive/dead"}}
    svcs = {s.id: s for s in normalize_services(_MENU_SOCK, health, None,
                                                sockets=frozenset())}
    assert svcs["dpi"].health.state == "degraded"


# ── LE REGISTRE NE SE VIDE PAS QUAND LE MENU DU HUB MANQUE ──────────────────
# Un `rm -f /var/cache/secubox/menu.json` (postinst d'appstore, d'annuaire) sans
# que personne n'appelle le hub pour le réécrire laissait le registre VIDE : le
# Hall retombait sur sa maquette (8 services) et un « jeton perdu » en avait
# l'air. Vu sur gk3 après le rassemblement #2050.
import api.main as main_mod


def test_un_menu_absent_ne_vide_pas_le_registre(monkeypatch, tmp_path):
    main_mod._cache["services"] = [{"id": "waf"}]
    monkeypatch.setattr(main_mod, "_CACHE_FILE", tmp_path / "services.json")
    monkeypatch.setattr(main_mod.registry, "load_menu_cache", lambda *a, **k: {"categories": []})
    assert main_mod._recompute() is False
    assert main_mod._cache["services"] == [{"id": "waf"}]
    assert not (tmp_path / "services.json").exists()


def test_un_menu_present_remplace_le_registre(monkeypatch, tmp_path):
    main_mod._cache["services"] = []
    monkeypatch.setattr(main_mod, "_CACHE_FILE", tmp_path / "services.json")
    monkeypatch.setattr(main_mod.registry, "load_menu_cache", lambda *a, **k: MENU)
    monkeypatch.setattr(main_mod, "systemd_batch", lambda *a, **k: HEALTH)
    assert main_mod._recompute() is True
    assert {s["id"] for s in main_mod._cache["services"]} == {"waf", "radio"}


def test_le_reveil_du_hub_interroge_son_statut_public(monkeypatch):
    appels = []

    class Faux:
        def __init__(self, chemin, timeout=0): appels.append(chemin)
        def request(self, methode, url): appels.append((methode, url))
        def getresponse(self): return type("R", (), {"status": 200, "read": lambda s: b""})()
        def close(self): pass
    monkeypatch.setattr(main_mod.registry, "_ConnexionUnix", Faux)
    assert main_mod.registry.reveille_hub("/run/secubox/aggregator.sock") is True
    assert ("GET", "/api/v1/hub/status") in appels
