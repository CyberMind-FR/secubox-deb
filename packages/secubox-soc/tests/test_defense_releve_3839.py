# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3839 (1.9.2) — console vue sur gk2 le 20/11 : « Gestes et blocages : relevé indisponible » (lecture WAF coupée à
3 s sur une box chargée, échec gardé en cache), nom technique du nœud, incidents en double, « ? » brut d'actord."""
# ruff: noqa: F811
import time

from test_defense_facade import LECTURE, admin, client, faux  # noqa: F401

from api import defense


def test_lectures_avec_delai_long(faux, client, admin, monkeypatch):
    delais = []
    origine = defense.substrat.lire

    def espion(source, chemin, entetes=None, delai=3.0):
        delais.append(delai)
        return origine(source, chemin, entetes=entetes, delai=delai)

    monkeypatch.setattr(defense.substrat, "lire", espion)
    client.get("/defense/actions", headers=LECTURE)
    client.get("/defense/threats", headers=LECTURE)
    assert delais and all(d == defense.DELAI_LECTURE_S >= 20 for d in delais)


def test_releve_tampon_garde_son_heure(faux, client, admin):
    j1 = client.get("/defense/actions", headers=LECTURE).json()
    assert j1["releve_a"] and j1["sources"]["waf"]["ok"] is True
    for e in defense._CACHE.values():
        e["retry_at"] = 0.0
        e["complet_a"] -= 300                     # 5 min : toujours dans le tampon
    faux.rep.pop(("waf", "/bans/history"))        # lecture WAF en échec
    j2 = client.get("/defense/actions", headers=LECTURE).json()
    assert j2["actions"] == j1["actions"] and j2["releve_a"] == j1["releve_a"]


def test_incidents_doublons_regroupes_et_outil_probable(faux, client, admin):
    t = int(time.time()) - 60
    faux.rep[("actord", "/overview")]["recents"] = [
        {"ts": t, "acteur": "ACT-0002", "type": "chrome", "module": "waf", "score": 50},
        {"ts": t + 1, "acteur": "ACT-0002", "type": "chrome", "module": "waf", "score": 50},
        {"ts": t + 2, "acteur": "ACT-0002", "type": "firefox", "module": "waf", "score": 50},
        {"ts": t + 3, "acteur": "ACT-3036", "type": "client-automatise?", "module": "waf", "score": 75},
    ]
    i = client.get("/defense/incidents?jours=7", headers=LECTURE).json()["incidents"]
    assert [(x["titre"], x["n"]) for x in i] == [
        ("ACT-0002 : chrome (waf)", 2), ("ACT-0002 : firefox (waf)", 1),
        ("ACT-3036 : client-automatise (probable) (waf)", 1)]


def test_pairs_silencieux_signales(faux, client, admin):
    faux.rep[("threatmesh", "/status")] = {"node": "sb-b3f61985b1b9", "mesh": {}, "mesh_total": 0}
    j = client.get("/defense/mesh", headers=LECTURE).json()
    assert j["pairs_silencieux"] is True
    assert j["noeuds"][0]["identifiant"] == "sb-b3f61985b1b9"
