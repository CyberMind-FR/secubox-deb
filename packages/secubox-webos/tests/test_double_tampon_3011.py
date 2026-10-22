# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3011 — double tampon réel du registre : une passe dégradée n'écrase pas le dernier relevé complet.

Sous charge, `systemctl list-units`, le `/health` de l'agrégateur et les cycles de vie des profils
expirent et rendaient un ensemble VIDE, indistinguable d'un vrai « rien » : ~110 modules tombaient
en `nosource` pendant un cycle. Désormais chaque sonde distingue « injoignable » (None) de « vide »,
une source injoignable garde sa dernière valeur, et le registre ne bascule que sur une passe utile.
"""
import asyncio
import json

import api.main as main_mod
from api import registry

MENU = {"categories": [{"items": [
    {"id": "waf", "name": "WAF", "category": "wall", "icon": "", "path": "/waf/", "installed": True, "active": True},
    {"id": "hardening", "name": "Hardening", "category": "wall", "icon": "", "path": "/hardening/", "installed": True, "active": True},
]}]}


class _Reponse:
    def __init__(self, corps):
        self._corps = corps
        self.status = 200

    def read(self):
        return json.dumps(self._corps).encode()


def _connexion(corps):
    class Faux:
        def __init__(self, *a, **k): pass
        def request(self, *a): pass
        def getresponse(self): return _Reponse(corps)
        def close(self): pass
    return Faux


def _injoignable(*a, **k):
    raise OSError("injoignable")


def test_sonde_montes_distingue_injoignable_de_vide(monkeypatch):
    monkeypatch.setattr(registry, "_ConnexionUnix", _connexion({"mounted": []}))
    assert registry.sonde_montes() == frozenset()
    monkeypatch.setattr(registry, "_ConnexionUnix", _connexion({"mounted": ["waf", 3]}))
    assert registry.sonde_montes() == frozenset({"waf"})
    monkeypatch.setattr(registry, "_ConnexionUnix", _injoignable)
    assert registry.sonde_montes() is None
    assert registry.modules_montes() == frozenset()        # l'ancien contrat reste : vide par défaut


def test_sonde_endormis_distingue_injoignable_de_vide(monkeypatch):
    monkeypatch.setattr(registry, "_ConnexionUnix", _connexion({"lifecycles": [{"id": "zia", "sleep_state": "asleep"}, {"id": "waf", "sleep_state": "awake"}]}))
    assert registry.sonde_endormis() == frozenset({"zia"})
    monkeypatch.setattr(registry, "_ConnexionUnix", _injoignable)
    assert registry.sonde_endormis() is None
    assert registry.modules_endormis() == frozenset()


def _prepare(monkeypatch, tmp_path, *, montes, endormis, sante):
    monkeypatch.setattr(main_mod, "_CACHE_FILE", tmp_path / "services.json")
    monkeypatch.setattr(main_mod.registry, "load_menu_cache", lambda *a, **k: MENU)
    monkeypatch.setattr(main_mod.registry, "load_exposure_cache", lambda *a, **k: {})
    monkeypatch.setattr(main_mod.registry, "sonde_montes", lambda *a, **k: montes)
    monkeypatch.setattr(main_mod.registry, "sonde_endormis", lambda *a, **k: endormis)
    monkeypatch.setattr(main_mod, "_releve_sante", lambda: sante)
    monkeypatch.setattr(main_mod, "_live_sockets", lambda *a, **k: frozenset())
    monkeypatch.setattr(main_mod.vignettes, "vignettes_presentes", lambda ids, *a, **k: set())
    monkeypatch.setattr(main_mod.registry, "reveille_hub", lambda *a, **k: True)


def test_une_source_injoignable_garde_sa_derniere_valeur(monkeypatch, tmp_path):
    _prepare(monkeypatch, tmp_path, montes=None, endormis=frozenset(), sante={"hardening": {"status": "error", "msg": "Failed"}})
    monkeypatch.setattr(main_mod, "_montes", frozenset({"waf"}))          # dernière valeur connue de l'agrégateur
    monkeypatch.setattr(main_mod, "_sante", {"waf": {"status": "ok", "msg": "Running"}})
    assert asyncio.run(main_mod._un_cycle()) is True
    s = {x["id"]: x for x in main_mod._cache["services"]}
    assert s["waf"]["status"] == "active"              # monté d'après la dernière sonde réussie, pas « nosource »
    assert s["hardening"]["status"] == "offline"       # la santé, elle, a répondu : on prend la nouvelle
    assert main_mod._montes == frozenset({"waf"})
    assert main_mod._sante == {"hardening": {"status": "error", "msg": "Failed"}}


def test_toutes_les_sources_injoignables_ne_basculent_pas(monkeypatch, tmp_path):
    _prepare(monkeypatch, tmp_path, montes=None, endormis=None, sante=None)
    main_mod._cache["services"] = [{"id": "waf", "status": "active"}]
    main_mod._cache["computed_at"] = 123.0
    assert asyncio.run(main_mod._un_cycle()) is False
    assert main_mod._cache["services"] == [{"id": "waf", "status": "active"}]
    assert main_mod._cache["computed_at"] == 123.0          # le Hall jugera « données périmées » si cela dure
    assert not (tmp_path / "services.json").exists()


def test_une_passe_complete_bascule_et_met_a_jour_les_sources(monkeypatch, tmp_path):
    _prepare(monkeypatch, tmp_path, montes=frozenset({"waf"}), endormis=frozenset({"hardening"}), sante={})
    monkeypatch.setattr(main_mod, "_montes", frozenset())
    monkeypatch.setattr(main_mod, "_endormis", frozenset())
    main_mod._cache["computed_at"] = 123.0
    assert asyncio.run(main_mod._un_cycle()) is True
    s = {x["id"]: x for x in main_mod._cache["services"]}
    assert s["waf"]["status"] == "active" and s["hardening"]["status"] == "idle"
    assert main_mod._montes == frozenset({"waf"}) and main_mod._endormis == frozenset({"hardening"})
    assert main_mod._cache["computed_at"] > 123.0
    assert json.loads((tmp_path / "services.json").read_text())["services"]


def test_un_menu_absent_reveille_le_hub_sans_toucher_au_registre(monkeypatch, tmp_path):
    _prepare(monkeypatch, tmp_path, montes=frozenset(), endormis=frozenset(), sante={})
    monkeypatch.setattr(main_mod.registry, "load_menu_cache", lambda *a, **k: {"categories": []})
    reveils = []
    monkeypatch.setattr(main_mod.registry, "reveille_hub", lambda *a, **k: reveils.append(1) or True)
    main_mod._cache["services"] = [{"id": "waf", "status": "active"}]
    assert asyncio.run(main_mod._un_cycle()) is False
    assert reveils == [1]
    assert main_mod._cache["services"] == [{"id": "waf", "status": "active"}]
