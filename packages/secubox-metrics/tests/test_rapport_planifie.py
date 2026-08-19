# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""Rapport planifié (#1059) : agrège une famille de vhosts → PDF → email.

L'orchestrateur reçoit ses collaborateurs par injection : on teste qu'il
demande le détail de la BONNE famille et expédie au BON destinataire, sans
toucher ni matplotlib ni SMTP.
"""
import rapport_planifie as rp


class FauxAgg:
    def __init__(self):
        self.appels = []

    def current(self, periode, grouper=False):
        self.appels.append(("current", periode, grouper))
        return {"vue": periode, "grouper": grouper}

    def detail(self, vhost, periode="semaine"):
        self.appels.append(("detail", vhost, periode))
        return {"detail": vhost}


def test_executer_agrege_la_famille_et_expedie_au_destinataire():
    agg = FauxAgg()
    envois = []

    def faux_pdf(vue, det):
        return b"%PDF-fake"

    def faux_envoyer(pdf, dest, portee, periode):
        envois.append((pdf, dest, portee, periode))
        return {"envoye": True, "destinataire": dest, "octets": len(pdf)}

    cfg = {"famille": "anibal-amiot", "destinataire": "gk2@secubox.in",
           "periode": "semaine"}
    res = rp.executer(agg, faux_pdf, faux_envoyer, cfg)

    # La vue d'ensemble est GROUPÉE (les familles fondues en une entrée)…
    assert ("current", "semaine", True) in agg.appels
    # …et le détail demandé est celui de la FAMILLE, pas d'un seul domaine.
    assert ("detail", "anibal-amiot", "semaine") in agg.appels
    # L'email part au destinataire configuré, avec le PDF produit ; la portée
    # nomme la famille (le sujet du mail devient « frequentation anibal-amiot »).
    assert envois == [(b"%PDF-fake", "gk2@secubox.in",
                       "anibal-amiot", "semaine")]
    assert res["envoye"] is True


def test_config_planifie_par_defaut_anibal_vers_gk2(monkeypatch, tmp_path):
    monkeypatch.setattr(rp, "CONF", tmp_path / "absent.toml")
    c = rp.config_planifie()
    assert c["famille"] == "anibal-amiot"
    assert c["destinataire"] == "gk2@secubox.in"
    assert c["periode"] == "semaine"


def test_config_planifie_lit_les_surcharges(monkeypatch, tmp_path):
    f = tmp_path / "metrics.toml"
    f.write_text('[rapport.planifie]\nfamille="autre"\n'
                 'destinataire="x@y.z"\nperiode="mois"\n')
    monkeypatch.setattr(rp, "CONF", f)
    c = rp.config_planifie()
    assert c["famille"] == "autre"
    assert c["destinataire"] == "x@y.z"
    assert c["periode"] == "mois"
