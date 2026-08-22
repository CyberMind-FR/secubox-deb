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

    def faux_envoyer(pdf, dest, portee, periode, resume=""):
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


def test_executer_transmet_le_resume_emoji_des_statuts():
    """Le détail porte des codes de retour → executer bâtit le résumé emoji et
    le passe à envoyer (corps du mail #1131an), sans que l'agrégateur le sache."""

    class AggAvecStatuts(FauxAgg):
        def detail(self, vhost, periode="semaine"):
            self.appels.append(("detail", vhost, periode))
            return {"detail": vhost, "statuts": {"200": 90, "404": 8, "500": 2}}

    recu = {}

    def faux_pdf(vue, det):
        return b"%PDF-fake"

    def faux_envoyer(pdf, dest, portee, periode, resume=""):
        recu["resume"] = resume
        return {"envoye": True, "destinataire": dest, "octets": len(pdf)}

    cfg = {"famille": "anibal-amiot", "destinataire": "gk2@secubox.in",
           "periode": "semaine"}
    rp.executer(AggAvecStatuts(), faux_pdf, faux_envoyer, cfg)

    # Le résumé est non vide et porte les émoticônes de classe et de type.
    assert "🟢 2xx" in recu["resume"]
    assert "🔍 404" in recu["resume"]
    assert "💥 500" in recu["resume"]


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


def test_resoudre_config_argv_surcharge_la_periode():
    base = {"famille": "anibal-amiot", "destinataire": "gk2@secubox.in",
            "periode": "semaine"}
    # Sans argument : la période de la config (le rapport hebdo).
    assert rp.resoudre_config([], base)["periode"] == "semaine"
    # Avec argument : il prime — c'est ainsi que le service quotidien demande
    # « jour » sans dupliquer la config.
    q = rp.resoudre_config(["jour"], base)
    assert q["periode"] == "jour"
    # La famille et le destinataire ne bougent pas.
    assert q["famille"] == "anibal-amiot"
    assert q["destinataire"] == "gk2@secubox.in"


def test_garde_temps_coupe_un_run_bloque(monkeypatch):
    """Un run qui dépasse son budget est coupé net (plus de hang de 80 min)."""
    import time as _t
    import pytest as _p
    monkeypatch.setattr(rp, "BUDGET_SECONDES", 1)

    def _bloque(*_a, **_k):
        _t.sleep(5)

    monkeypatch.setattr(rp, "executer", _bloque)
    t0 = _t.monotonic()
    with _p.raises(rp._GardeTempsDepasse):
        rp._executer_borne(None, None, None, {})
    assert _t.monotonic() - t0 < 3, "le garde-temps aurait dû couper vers 1s"
