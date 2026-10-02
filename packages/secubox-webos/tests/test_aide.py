# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Aide des cartes du Hall (#1664) : source unique, extraction, lecture visiteur."""
import asyncio
import re
from pathlib import Path

from api import aide

HALL = Path(__file__).resolve().parents[1] / "www" / "hall" / "index.html"

RADIO = {"metrics": [{"id": "listeners", "value": 3}, {"id": "tracks", "value": 115}],
         "content": {"title": "ERA - Ameno"}}


def test_chemins():
    assert aide.extraire(RADIO, "metrics[id=listeners].value") == 3
    assert aide.extraire(RADIO, "content.title") == "ERA - Ameno"
    assert aide.extraire({"p": [{"name": "TLS"}, {"name": "DNS"}]}, "p.1.name") == "DNS"
    assert aide.extraire({"items": [{"t": 2}, {"t": 5}]}, "items[].t") == [2, 5]
    assert aide.extraire(RADIO, "metrics[id=absent].value") is None
    assert aide.extraire(RADIO, "rien.du.tout") is None


def test_valeurs():
    z = {"appareils": [{"joignable": True}, {"joignable": False}, {"joignable": True}]}
    assert aide.valeur({"compte": "appareils"}, z) == 3
    assert aide.valeur({"compte": "appareils[joignable=true]"}, z) == 2
    assert aide.valeur({"compte": "[kept=1]"}, [{"kept": 1}, {"kept": 0}]) == 1
    assert aide.valeur({"compte": ""}, [1, 2, 3]) == 3
    assert aide.valeur({"somme": "items[].threads"}, {"items": [{"threads": 8}, {"threads": 7}]}) == 15
    # un texte n'est rendu que s'il est déclaré texte — jamais un objet
    assert aide.valeur({"chemin": "content.title"}, RADIO) is None
    assert aide.valeur({"chemin": "content.title", "format": "texte"}, RADIO) == "ERA - Ameno"
    assert aide.valeur({"chemin": "content"}, RADIO) is None


def test_source_couvre_chaque_carte_du_hall():
    """Chaque carte du Hall a son aide réelle — plus de « service souverain »."""
    cartes = aide.charger()
    ids = set(re.findall(r'\{id:"([a-z0-9-]+)",\s*label:', HALL.read_text(encoding="utf-8")))
    assert ids, "FEATURED introuvable"
    manquantes = ids - set(cartes)
    assert not manquantes, f"cartes sans aide : {sorted(manquantes)}"
    for c in cartes.values():
        assert c.get("role") and len(c["role"]) > 30, c["id"]
        assert c.get("usage"), c["id"]
        assert c.get("acces") in ("public", "session", "lan"), c["id"]
        for m in c.get("metriques") or []:
            assert m.get("libelle") and m.get("url", "").startswith("/"), c["id"]
            assert sum(k in m for k in ("chemin", "compte", "somme")) == 1, (c["id"], m)


def test_lecture_en_visiteur_et_sans_donnee_gardee():
    vus = []

    async def get(hote, url):
        vus.append((hote, url))
        return RADIO

    c = {"id": "radio", "metriques": [
        {"libelle": "auditeurs", "url": "/r", "chemin": "metrics[id=listeners].value"},
        {"libelle": "à l'antenne", "url": "/r", "chemin": "content.title", "format": "texte"},
        {"libelle": "gardé", "url": "/secret", "chemin": "x", "session": True}]}
    lec = aide.Lecteur("gk2.secubox.in", _get=get)
    m = asyncio.run(lec.metriques(c))
    assert [x["valeur"] for x in m] == [3, "ERA - Ameno", None]
    assert vus == [("hall.gk2.secubox.in", "/r")]          # une lecture par source, jamais /secret
    asyncio.run(lec.metriques(c))
    assert len(vus) == 1                                     # cache


def test_panne_de_source_rend_none():
    async def get(hote, url):
        raise OSError("injoignable")

    m = asyncio.run(aide.Lecteur("x", _get=get).metriques(
        {"id": "a", "metriques": [{"libelle": "n", "url": "/n", "chemin": "n"}]}))
    assert m[0]["valeur"] is None


def test_phrase_et_trouver():
    cartes = aide.charger()
    c = cartes["radio"]
    p = aide.phrase(c, [{"libelle": "auditeurs", "valeur": 1204, "format": "nombre"},
                        {"libelle": "volume", "valeur": 3 * 1024 ** 3, "format": "octets"},
                        {"libelle": "absent", "valeur": None, "format": "nombre"}])
    assert p.startswith("Radio : ") and "auditeurs : 1 204" in p and "volume : 3.0 Go" in p
    assert "absent" not in p
    assert aide.trouver(cartes, "à quoi sert la carte radio ?")["id"] == "radio"
    assert aide.trouver(cartes, "c'est quoi Zigbee")["id"] == "zigbee"
    assert aide.trouver(cartes, "bonjour") is None


def test_publique_ne_livre_pas_les_url_visiteur():
    c = aide.charger()["dpi"]
    p = aide.publique(c)
    assert all(m["session"] and m["url"] for m in p["metriques"])
    r = aide.publique(aide.charger()["radio"])
    assert all(m["url"] is None for m in r["metriques"])
