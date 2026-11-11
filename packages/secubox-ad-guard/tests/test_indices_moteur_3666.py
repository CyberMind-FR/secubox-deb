# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Indices du maillage (#3666) dans la détection et le moteur auto : une coupure suffit, domaine exact, garde des catégories
protégées, légitime ailleurs, appareil guidé, retrait de l'essai quand l'indice disparaît."""
import time

import pytest

from api import dnstv, dnstv_auto as M, dnstv_detect as D, dnstv_regles as R, dnstv_taxonomie as T
from api.dnstv_indices import Index

IP = "192.168.1.95"
ETAT = {"actif": True, "clients": [{"ip": IP, "nom": "TV banc", "mode": "auto"}, {"ip": "192.168.1.9", "nom": "Autre", "mode": "observe"}]}
REGLAGE = M.Reglage(declencheurs=("fwmrm.net",))            # auto_essai faux par défaut
PUB = "pub-indice.regie-exemple.net"
CLASSES = {"7cd77.v.fwmrm.net": "advertising", "flux.regie-exemple.net": "contenu"}


def classer(d):
    return CLASSES.get(d, "")


def evt(ts, d, client=IP, decision="ALLOWED"):
    return dnstv.Evenement(ts, client, d, "A", "NXDOMAIN" if decision == "BLOCKED" else "NOERROR", decision)


@pytest.fixture
def magasin(tmp_path):
    return dnstv.Magasin(tmp_path / "m.db")


def charger(magasin, evts):
    magasin.ajouter([(e, "") for e in evts])


def coupure(t, *domaines):
    return [evt(t, "7cd77.v.fwmrm.net")] + [evt(t + 3 + i, d) for i, d in enumerate(domaines)]


def indice(*domaines, par=("gk2",), legitimes=None):
    return Index(confirmes={d: {n: "PUBLICITE" for n in par} for d in domaines},
                 legitimes={d: set(v) for d, v in (legitimes or {}).items()})


def regles_de(r):
    return {x["domaine"]: x for x in r.liste()}


def test_une_coupure_suffit_et_inconnu_leve(magasin):
    t = int(time.time())
    charger(magasin, coupure(t - 600, PUB))
    temoin = R.Regles()
    M.tick(ETAT, temoin, magasin, classer, REGLAGE, t)
    assert PUB not in regles_de(temoin)                        # sans indice : une seule coupure, INCONNU, rien
    r = R.Regles()
    res = M.tick(ETAT, r, magasin, classer, REGLAGE, t, indices=indice(PUB))
    x = regles_de(r)[PUB]
    assert x["score"] == D.SCORE_INDICE == 100 and x["indice"] == ["gk2"]
    assert x["etat"] == "essai" and x["motif"] == "essai automatique (indice du maillage)"
    assert x["historique"][0]["motif"] == "suggéré par gk2"
    assert res["applique"] is True and PUB in r.actives("tv-banc")


def test_partage_part_aussi_en_essai(magasin):
    t = int(time.time())
    charger(magasin, [evt(t - 1200, PUB)] + coupure(t - 600, PUB))
    r = R.Regles()
    M.tick(ETAT, r, magasin, classer, REGLAGE, t, indices=indice(PUB))
    x = regles_de(r)[PUB]
    assert x["risque"] == "partage" and x["etat"] == "essai"


def test_jamais_sans_vue_locale(magasin):
    t = int(time.time())
    charger(magasin, coupure(t - 600, "autre.regie-exemple.net") + [evt(t - 100, PUB)])   # vu, mais hors coupure
    r = R.Regles()
    M.tick(ETAT, r, magasin, classer, REGLAGE, t, indices=indice(PUB, "jamais-vu.regie-exemple.net"))
    assert PUB not in regles_de(r) and "jamais-vu.regie-exemple.net" not in regles_de(r)


def test_indice_jamais_declencheur(magasin):
    t = int(time.time())
    charger(magasin, [evt(t - 600, PUB), evt(t - 597, "autre.regie-exemple.net")])         # aucun déclencheur : aucune coupure
    r = R.Regles()
    M.tick(ETAT, r, magasin, classer, REGLAGE, t, indices=indice(PUB))
    assert r.liste() == []


def test_protegee_reste_protegee(magasin):
    t = int(time.time())
    flux = "flux.regie-exemple.net"                            # classé STREAMING localement
    assert T.refus_indice(T.Taxonomie(listes=classer), flux) is not None
    assert T.refus_indice(T.Taxonomie(listes=classer), PUB) is None                          # INCONNU levé par l'indice
    assert T.refus_auto(T.Taxonomie(listes=classer), PUB) is not None                        # mais pas par le moteur seul
    charger(magasin, coupure(t - 600, flux))
    r = R.Regles()
    M.tick(ETAT, r, magasin, classer, M.Reglage(declencheurs=("fwmrm.net",), auto_essai=True), t, indices=indice(flux))
    assert regles_de(r)[flux]["etat"] == "candidat"


def test_legitime_ailleurs_freine(magasin):
    t = int(time.time())
    charger(magasin, coupure(t - 600, PUB))
    r = R.Regles()
    M.tick(ETAT, r, magasin, classer, REGLAGE, t, indices=indice(PUB, legitimes={PUB: {"gk1"}}))
    x = regles_de(r)[PUB]
    assert x["etat"] == "candidat" and x["motif"] == "légitime chez gk1"


def test_appareil_guide_jamais_seul(magasin):
    t = int(time.time())
    charger(magasin, coupure(t - 600, PUB))
    r = R.Regles()
    M.tick(ETAT, r, magasin, classer, REGLAGE, t, guides=frozenset({"tv-banc"}), indices=indice(PUB))
    assert regles_de(r)[PUB]["etat"] == "candidat"


def test_aucun_appareil_auto(magasin):
    t = int(time.time())
    etat = {"actif": True, "clients": [{"ip": IP, "nom": "TV banc", "mode": "observe"}]}
    charger(magasin, coupure(t - 600, PUB))
    r = R.Regles()
    res = M.tick(etat, r, magasin, classer, REGLAGE, t, indices=indice(PUB))
    assert r.liste() == [] and res["changements"] == [] and res["applique"] is False


def test_retrait_quand_l_indice_disparait(magasin):
    t = int(time.time())
    charger(magasin, coupure(t - 600, PUB))
    r = R.Regles()
    M.tick(ETAT, r, magasin, classer, REGLAGE, t, indices=indice(PUB))
    assert regles_de(r)[PUB]["etat"] == "essai"
    conf = r.proposer("tv-banc", "confirme.regie-exemple.net", 100, "faible", t, indice=["gk2"])["id"]
    r.transiter(conf, "essai", "auto", "essai automatique (indice du maillage)", t)
    r.transiter(conf, "confirme", "admin", "", t)
    local = r.proposer("tv-banc", "local.regie-exemple.net", 50, "faible", t)["id"]          # essai sans indice : pas concerné
    r.transiter(local, "essai", "admin", "", t)
    res = M.tick(ETAT, r, magasin, classer, REGLAGE, t + 60, indices=Index())
    x = regles_de(r)
    assert x[PUB]["etat"] == "retire" and x[PUB]["motif"] == "indice retiré"
    assert x["confirme.regie-exemple.net"]["etat"] == "confirme" and x["local.regie-exemple.net"]["etat"] == "essai"
    assert res["applique"] is True
    assert {"appareil": "tv-banc", "domaine": PUB, "de": "essai", "vers": "retire", "motif": "indice retiré"} in res["changements"]


def test_retrait_quand_un_producteur_le_declare_legitime(magasin):
    t = int(time.time())
    charger(magasin, coupure(t - 600, PUB))
    r = R.Regles()
    M.tick(ETAT, r, magasin, classer, REGLAGE, t, indices=indice(PUB))
    M.tick(ETAT, r, magasin, classer, REGLAGE, t + 60, indices=indice(PUB, legitimes={PUB: {"gk1"}}))
    assert regles_de(r)[PUB]["etat"] == "retire"


def test_sans_indices_le_retrait_n_agit_pas(magasin):
    t = int(time.time())
    charger(magasin, coupure(t - 600, PUB))
    r = R.Regles()
    M.tick(ETAT, r, magasin, classer, REGLAGE, t, indices=indice(PUB))
    M.tick(ETAT, r, magasin, classer, REGLAGE, t + 60)                                          # indices=None : rien ne change
    assert regles_de(r)[PUB]["etat"] == "essai"


def test_domaine_exact_jamais_parent(magasin):
    t = int(time.time())
    variantes = [f"a{i}.x.regie-exemple.com" for i in (1, 2, 3)]
    charger(magasin, coupure(t - 3000, *variantes) + coupure(t - 1500, *variantes))
    temoin = R.Regles()
    M.tick(ETAT, temoin, magasin, classer, REGLAGE, t)
    assert regles_de(temoin)["x.regie-exemple.com"]["risque"] == "variable"   # sans indice : regroupées sous le parent
    r = R.Regles()
    M.tick(ETAT, r, magasin, classer, REGLAGE, t, indices=indice(variantes[0]))
    x = regles_de(r)
    assert x[variantes[0]]["indice"] == ["gk2"] and x[variantes[0]]["etat"] == "essai"
    assert "x.regie-exemple.com" not in x


def test_detecter_indice_exact_et_score():
    t = 1_000_000
    evts = [{"ts": t, "domaine": "7cd77.v.fwmrm.net", "decision": "ALLOWED"}, {"ts": t + 3, "domaine": PUB, "decision": "ALLOWED"}]
    cands = {c.domaine: c for c in D.detecter(evts, lambda d: d.endswith("fwmrm.net"), classer, set(), indices={PUB})}
    assert cands[PUB].score == 100 and cands[PUB].risque == "faible" and cands[PUB].coupures == 1
    assert PUB not in {c.domaine for c in D.detecter(evts, lambda d: d.endswith("fwmrm.net"), classer, set())}


def test_motif_borne_et_indice_plafonne(magasin):
    t = int(time.time())
    noms = tuple(f"box-{i:02d}-" + "n" * 20 for i in range(12))
    charger(magasin, coupure(t - 600, PUB))
    r = R.Regles()
    M.tick(ETAT, r, magasin, classer, REGLAGE, t, indices=indice(PUB, par=noms + ("NOM INVALIDE",)))
    x = regles_de(r)[PUB]
    m = x["historique"][0]["motif"]
    assert m.startswith("suggéré par box-00-") and len(m) <= 120
    assert x["indice"] == sorted(noms)[:8] and x["etat"] == "essai"


def test_valider_regle_indice_borne():
    base = {"appareil": "tv-banc", "domaine": PUB, "etat": "candidat"}
    assert R.valider_regle({**base, "indice": ["gk2", "gk1"]})["indice"] == ["gk2", "gk1"]
    assert "indice" not in R.valider_regle(base) and "indice" not in R.valider_regle({**base, "indice": []})
    for mauvais in ([f"gk{i}" for i in range(9)], ["GK 2"], "gk2", [2], ["x" * 33]):
        with pytest.raises(R.ErreurRegle):
            R.valider_regle({**base, "indice": mauvais})
    r = R.Regles()
    assert r.proposer("tv-banc", PUB, 100, "faible", 1, indice=["gk2"])["indice"] == ["gk2"]
    assert R.Regles.depuis_dict(r.vers_dict()).liste()[0]["indice"] == ["gk2"]
