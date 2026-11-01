# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Lot 4 (#3374), arbitrage 3 : les replis publicitaires deviennent candidats du moteur AUTO et entrent en ESSAI, garde du lot 2 comprise."""
import time
from pathlib import Path

import pytest

from api import dnstv, dnstv_auto as M, dnstv_dpi as D, dnstv_regles as R, dnstv_taxonomie as T

LISTES = Path(__file__).resolve().parents[1] / "lists"
IP = "192.168.1.95"
ETAT = {"actif": True, "clients": [{"ip": IP, "nom": "TV banc", "mode": "auto", "mac": "00:24:d4:00:00:01"}]}


def evt(ts, d, decision="ALLOWED"):
    return dnstv.Evenement(ts, IP, d, "A", "NXDOMAIN" if decision == "BLOCKED" else "NOERROR", decision)


@pytest.fixture
def magasin(tmp_path):
    m = dnstv.Magasin(tmp_path / "m.db")
    t = int(time.time())
    m.ajouter([(e, "") for e in (evt(t - 100, "pagead2.googlesyndication.com", "BLOCKED"), evt(t - 97, "metaproxy.francetvpub.fr"),
                                 evt(t - 95, "m.media-amazon.com"), evt(t - 94, "license.oqee.net"))])
    return m


def replis(magasin):
    taxo = T.Taxonomie.depuis_dossier(LISTES)
    return {"tv-banc": D.correler(magasin.evenements([IP], 0), lambda d: taxo.classer(d)["categorie"])}


def test_repli_publicitaire_entre_en_essai_avec_sa_raison(magasin):
    r = R.Regles()
    M.tick(ETAT, r, magasin, lambda d: "", M.Reglage(auto_essai=True), int(time.time()), taxo=T.Taxonomie.depuis_dossier(LISTES),
           replis=replis(magasin))
    x = {y["domaine"]: y for y in r.liste()}
    assert x["metaproxy.francetvpub.fr"]["etat"] == "essai"
    assert any("apparu 3 s après le blocage de pagead2.googlesyndication.com" in h.get("motif", "")
               for h in x["metaproxy.francetvpub.fr"].get("historique", [])) or "repli" in x["metaproxy.francetvpub.fr"]["motif"]
    assert "m.media-amazon.com" not in r.actives("tv-banc") and "license.oqee.net" not in r.actives("tv-banc")


def test_sans_essai_automatique_le_repli_reste_candidat(magasin):
    r = R.Regles()
    M.tick(ETAT, r, magasin, lambda d: "", M.Reglage(auto_essai=False), int(time.time()), taxo=T.Taxonomie.depuis_dossier(LISTES),
           replis=replis(magasin))
    assert {y["domaine"]: y["etat"] for y in r.liste()}.get("metaproxy.francetvpub.fr") == "candidat"
