# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Non-régression #2146 / lot 4 (#3374), B2 : imasdk.googleapis.com bloqué = replay Free sans fin. Il reste PROTÉGÉ : jamais candidat de
repli, jamais en essai ni bloqué automatiquement."""
import time
from pathlib import Path

from api import dnstv, dnstv_auto as M, dnstv_dpi as D, dnstv_regles as R, dnstv_taxonomie as T

LISTES = Path(__file__).resolve().parents[1] / "lists"
TAXO = T.Taxonomie.depuis_dossier(LISTES)
IP = "192.168.1.95"
ETAT = {"actif": True, "clients": [{"ip": IP, "nom": "TV banc", "mode": "auto", "mac": "00:24:d4:00:00:01"}]}


def test_imasdk_est_protege():
    c = TAXO.classer("imasdk.googleapis.com")
    assert c["protegee"] is True and c["categorie"] in T.PROTEGEES
    assert T.refus_auto(TAXO, "imasdk.googleapis.com") is not None


def test_imasdk_jamais_candidat_de_repli():
    e = [{"ts": 0, "domaine": "pagead2.googlesyndication.com", "decision": "BLOCKED"},
         {"ts": 2, "domaine": "imasdk.googleapis.com", "decision": "ALLOWED"}]
    dec = D.correler(e, lambda d: TAXO.classer(d)["categorie"])
    assert [d["type"] for d in dec] == ["repli-protege"] and D.candidats_repli(dec) == []


def test_imasdk_jamais_en_essai_par_le_moteur(tmp_path):
    m = dnstv.Magasin(tmp_path / "m.db")
    t = int(time.time())
    m.ajouter([(dnstv.Evenement(t - k, IP, d, "A", "NOERROR", "ALLOWED"), "") for k, d in ((90, "imasdk.googleapis.com"),)])
    r = R.Regles()
    M.tick(ETAT, r, m, lambda d: "advertising" if "imasdk" in d else "", M.Reglage(auto_essai=True, confirmation_auto=True), t, taxo=TAXO)
    assert "imasdk.googleapis.com" not in r.actives("tv-banc")
