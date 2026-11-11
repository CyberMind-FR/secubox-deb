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
    assert x["etat"] == "essai" and x["motif"] == "essai automatique, suggéré par gk2"           # F7 : l'origine est nommée
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
    """B : l'indice disparu, l'essai né de lui est OUBLIÉ (reproposable) ; confirmé par l'admin ou essai local : intouchés."""
    t = int(time.time())
    charger(magasin, coupure(t - 600, PUB))
    r = R.Regles()
    M.tick(ETAT, r, magasin, classer, REGLAGE, t, indices=indice(PUB))
    assert regles_de(r)[PUB]["etat"] == "essai"
    conf = r.proposer("tv-banc", "confirme.regie-exemple.net", 100, "faible", t, indice=["gk2"])["id"]
    r.transiter(conf, "essai", "auto", "essai automatique, suggéré par gk2", t)
    r.transiter(conf, "confirme", "admin", "", t)
    local = r.proposer("tv-banc", "local.regie-exemple.net", 50, "faible", t)["id"]          # essai sans indice : pas concerné
    r.transiter(local, "essai", "admin", "", t)
    res = M.tick(ETAT, r, magasin, classer, REGLAGE, t + 60, indices=Index())
    x = regles_de(r)
    assert PUB not in x
    assert x["confirme.regie-exemple.net"]["etat"] == "confirme" and x["local.regie-exemple.net"]["etat"] == "essai"
    assert res["applique"] is True
    assert {"appareil": "tv-banc", "domaine": PUB, "de": "essai", "vers": "", "motif": "indice retiré"} in res["changements"]
    M.tick(ETAT, r, magasin, classer, REGLAGE, t + 120, indices=indice(PUB))                  # l'indice revient : reproposé
    assert regles_de(r)[PUB]["etat"] == "essai"


def test_retrait_quand_un_producteur_le_declare_legitime(magasin):
    t = int(time.time())
    charger(magasin, coupure(t - 600, PUB))
    r = R.Regles()
    M.tick(ETAT, r, magasin, classer, REGLAGE, t, indices=indice(PUB))
    res = M.tick(ETAT, r, magasin, classer, REGLAGE, t + 60, indices=indice(PUB, legitimes={PUB: {"gk1"}}))
    assert {"appareil": "tv-banc", "domaine": PUB, "de": "essai", "vers": "", "motif": "indice retiré"} in res["changements"]
    assert regles_de(r)[PUB]["etat"] == "candidat" and regles_de(r)[PUB]["motif"] == "légitime chez gk1"   # oublié puis candidat


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


# ── fix round 1 ────────────────────────────────────────────────────────────────────────────────────────

def activite(t, n=150):
    return [evt(t - i * 5, "api.contenu-habituel.fr") for i in range(n)]


def essai_d_indice(magasin, r, t0):
    charger(magasin, coupure(t0 - 600, PUB))
    M.tick(ETAT, r, magasin, classer, REGLAGE, t0, indices=indice(PUB))
    assert regles_de(r)[PUB]["etat"] == "essai"


def test_essai_pose_par_l_admin_jamais_retire(magasin):
    """A : un essai que l'administrateur a lancé n'est jamais retiré par les indices."""
    t = int(time.time())
    charger(magasin, coupure(t - 600, PUB))
    r = R.Regles()
    leg = indice(PUB, legitimes={PUB: {"gk1"}})
    M.tick(ETAT, r, magasin, classer, REGLAGE, t, indices=leg)
    x = regles_de(r)[PUB]
    assert x["etat"] == "candidat" and x["indice"] == ["gk2"]
    r.transiter(x["id"], "essai", "admin", "", t)
    M.tick(ETAT, r, magasin, classer, REGLAGE, t + 60, indices=leg)
    M.tick(ETAT, r, magasin, classer, REGLAGE, t + 120, indices=Index())
    assert regles_de(r)[PUB]["etat"] == "essai"


def test_index_illisible_ne_retire_rien(magasin):
    """B : lecture ratée (dossier ou index.json absent / illisible) : aucun retrait."""
    t = int(time.time())
    r = R.Regles()
    essai_d_indice(magasin, r, t)
    M.tick(ETAT, r, magasin, classer, REGLAGE, t + 60, indices=Index(lisible=False))
    assert regles_de(r)[PUB]["etat"] == "essai"


def test_producteur_indisponible_ne_retire_pas(magasin):
    t = int(time.time())
    r = R.Regles()
    essai_d_indice(magasin, r, t)
    M.tick(ETAT, r, magasin, classer, REGLAGE, t + 60, indices=Index(indisponibles={"gk2"}))
    assert regles_de(r)[PUB]["etat"] == "essai"
    M.tick(ETAT, r, magasin, classer, REGLAGE, t + 120, indices=Index(indisponibles={"gk9"}))
    assert PUB not in regles_de(r)


def test_rafale_retire_toujours_un_essai_d_indice(magasin):
    """B : un retrait par signal local garde l'état `retire` (jamais reproposé 30 jours)."""
    t = int(time.time())
    r = R.Regles()
    essai_d_indice(magasin, r, t)
    t2 = t + 600
    charger(magasin, [evt(t2 - m * 60 - (k * 60) // 80, PUB, decision="BLOCKED") for m in range(6) for k in range(80)])
    M.tick(ETAT, r, magasin, classer, REGLAGE, t2, indices=indice(PUB))
    x = regles_de(r)[PUB]
    assert x["etat"] == "retire" and "rafale" in x["motif"]


def test_echeance_confirme_l_essai_d_indice(magasin):
    """C : à l'échéance, sans régression, l'essai né d'un indice est confirmé (même `confirmation_auto` faux, même INCONNU) ;
    il n'est pas publié (pas d'écho) et reste soumis au retrait si l'indice disparaît."""
    from api import dnstv_indices as I
    t = int(time.time())
    t0 = t - R.ESSAI_S - 60
    r = R.Regles()
    essai_d_indice(magasin, r, t0)
    charger(magasin, activite(t - 100))
    M.tick(ETAT, r, magasin, classer, REGLAGE, t, indices=indice(PUB))
    x = regles_de(r)[PUB]
    assert x["etat"] == "confirme" and x["motif"] == "confirmé, suggéré par gk2" and x["historique"][-1]["origine"] == "auto"
    assert PUB not in I.contenu(r, [], T.Taxonomie(listes=classer))["indices"]
    M.tick(ETAT, r, magasin, classer, REGLAGE, t + 60, indices=indice(PUB, legitimes={PUB: {"gk1"}}))
    assert regles_de(r)[PUB]["etat"] == "candidat"                       # confirmé par le moteur : oublié, puis candidat


def test_echeance_peu_actif_ou_index_illisible_prolonge(magasin):
    t = int(time.time())
    t0 = t - R.ESSAI_S - 60
    r = R.Regles()
    essai_d_indice(magasin, r, t0)
    charger(magasin, activite(t - 100, n=5))
    M.tick(ETAT, r, magasin, classer, REGLAGE, t, indices=indice(PUB))
    x = regles_de(r)[PUB]
    assert x["etat"] == "essai" and x["fin_essai"] > t                   # peu actif : prolongé
    t3 = x["fin_essai"] + 10
    M.tick(ETAT, r, magasin, classer, REGLAGE, t3, indices=Index(lisible=False))
    x = regles_de(r)[PUB]
    assert x["etat"] == "essai" and x["fin_essai"] > t3                  # index illisible : la protection n'est pas retirée


def test_echeance_categorie_protegee_n_est_pas_confirmee(magasin):
    t = int(time.time())
    t0 = t - R.ESSAI_S - 60
    r = R.Regles()
    essai_d_indice(magasin, r, t0)
    charger(magasin, activite(t - 100))
    streaming = {**CLASSES, PUB: "contenu"}                              # corrigé STREAMING depuis
    M.tick(ETAT, r, magasin, lambda d: streaming.get(d, ""), REGLAGE, t, indices=indice(PUB))
    assert regles_de(r)[PUB]["etat"] == "retire"                         # expiration ordinaire


def test_candidat_existant_passe_en_essai(magasin):
    """D : un candidat auto existant reçoit l'indice et entre à l'essai ; rejeté, retiré ou proposé par l'admin : intouchés."""
    t = int(time.time())
    charger(magasin, coupure(t - 3000, PUB) + coupure(t - 1500, PUB))
    r = R.Regles()
    M.tick(ETAT, r, magasin, classer, REGLAGE, t)
    assert regles_de(r)[PUB]["etat"] == "candidat" and "indice" not in regles_de(r)[PUB]
    rej = r.proposer("tv-banc", "rejete.regie-exemple.net", 50, "faible", t)["id"]
    r.transiter(rej, "rejete", "admin", "", t)
    ret = r.proposer("tv-banc", "retire.regie-exemple.net", 50, "faible", t)["id"]
    r.transiter(ret, "retire", "admin", "", t)
    r.proposer("tv-banc", "admin.regie-exemple.net", 50, "faible", t, origine="admin")
    autres = ("rejete.regie-exemple.net", "retire.regie-exemple.net", "admin.regie-exemple.net")
    avant = {d: regles_de(r)[d] for d in autres}
    M.tick(ETAT, r, magasin, classer, REGLAGE, t + 60, indices=indice(PUB, *autres))
    x = regles_de(r)[PUB]
    assert x["etat"] == "essai" and x["indice"] == ["gk2"] and x["motif"] == "essai automatique, suggéré par gk2"
    assert {d: regles_de(r)[d] for d in autres} == avant


def test_candidat_existant_appareil_guide_reste_candidat(magasin):
    t = int(time.time())
    charger(magasin, coupure(t - 3000, PUB) + coupure(t - 1500, PUB))
    r = R.Regles()
    M.tick(ETAT, r, magasin, classer, REGLAGE, t)
    M.tick(ETAT, r, magasin, classer, REGLAGE, t + 60, guides=frozenset({"tv-banc"}), indices=indice(PUB))
    assert regles_de(r)[PUB]["etat"] == "candidat"


def test_parent_variable_sans_indice(magasin):
    """E : un candidat né d'un regroupement (risque variable) ne porte jamais l'indice."""
    t = int(time.time())
    variantes = [f"a{i}.x.regie-exemple.com" for i in (1, 2, 3)]
    charger(magasin, coupure(t - 3000, *variantes) + coupure(t - 1500, *variantes))
    r = R.Regles()
    M.tick(ETAT, r, magasin, classer, REGLAGE, t, indices=indice("x.regie-exemple.com"))
    x = regles_de(r)["x.regie-exemple.com"]
    assert x["risque"] == "variable" and x["etat"] == "candidat" and "indice" not in x and not x["motif"].startswith("suggéré")


def test_legitime_l_emporte_sur_un_producteur_indisponible(magasin):
    """Fix round 2 : un légitime déclaré par un producteur lisible fait oublier la règle, même si un producteur de son `indice`
    est indisponible ; `indisponibles` ne protège que du cas « plus aucun confirmateur »."""
    t = int(time.time())
    r = R.Regles()
    essai_d_indice(magasin, r, t)
    ix = Index(legitimes={PUB: {"gk1"}}, indisponibles={"gk2"})
    res = M.tick(ETAT, r, magasin, classer, REGLAGE, t + 60, indices=ix)
    assert PUB not in regles_de(r)
    assert {"appareil": "tv-banc", "domaine": PUB, "de": "essai", "vers": "", "motif": "indice retiré"} in res["changements"]


def test_prolongations_ne_chassent_pas_l_entree_en_essai(magasin):
    """Fix round 3 : une prolongation remplace la précédente dans l'historique (plafonné à 10) ; après 12 prolongations l'entrée
    à l'essai par le moteur reste lisible. Correctif final (B1) : au-delà de 3 prolongations consécutives, l'essai né d'un indice
    n'est plus ni prolongé ni confirmé : l'expiration ordinaire le retire."""
    t = int(time.time())
    t0 = t - R.ESSAI_S - 3600
    r = R.Regles()
    essai_d_indice(magasin, r, t0)
    rid = regles_de(r)[PUB]["id"]
    for k in range(12):
        r.prolonger_essai(rid, t0 + 60 + k)
    x = r.get(rid)
    assert M._ne_du_moteur(x) and len(x["historique"]) == 3                 # candidat, essai, UNE prolongation
    assert [h["vers"] for h in x["historique"]] == ["candidat", "essai", "essai"] and x["historique"][-1]["ts"] == t0 + 71
    assert x["prolongations"] == 12
    charger(magasin, activite(t - 100))
    M.tick(ETAT, r, magasin, classer, REGLAGE, t, indices=indice(PUB))
    assert r.get(rid)["etat"] == "retire"


def test_prolongation_sans_precedente_s_ajoute():
    r = R.Regles()
    rid = r.proposer("tv-banc", PUB, 50, "faible", 1)["id"]
    r.transiter(rid, "essai", "auto", "x", 2)
    r.prolonger_essai(rid, 3)
    r.prolonger_essai(rid, 4, "autre motif")
    assert [(h["de"], h["vers"], h["ts"], h["motif"]) for h in r.get(rid)["historique"]] == [
        ("", "candidat", 1, "proposé"), ("candidat", "essai", 2, "x"), ("essai", "essai", 4, "autre motif")]


# ── correctif final (B1, F2, F7) ─────────────────────────────────────────────────────────────────────────────────

def test_b1_prolongations_plafonnees_a_trois(magasin):
    """B1 : lecture locale en panne (index illisible) : l'essai né d'un indice est prolongé 3 fois de suite au plus, puis
    l'expiration ordinaire le retire — une panne (ou un pair) ne fige jamais un blocage."""
    t = int(time.time())
    r = R.Regles()
    essai_d_indice(magasin, r, t)
    rid = regles_de(r)[PUB]["id"]
    for k in range(1, 4):
        echeance = r.get(rid)["fin_essai"] + 10
        charger(magasin, activite(echeance - 100))
        M.tick(ETAT, r, magasin, classer, REGLAGE, echeance, indices=Index(lisible=False))
        x = r.get(rid)
        assert x["etat"] == "essai" and x["prolongations"] == k and x["motif"] == M.MOTIF_INDICE_INDISPONIBLE
    echeance = r.get(rid)["fin_essai"] + 10
    M.tick(ETAT, r, magasin, classer, REGLAGE, echeance, indices=Index(lisible=False))
    assert r.get(rid)["etat"] == "retire"


def test_b1_regression_eprouvee_meme_indices_indisponibles(magasin):
    """B1 : même quand on prolongerait faute de lecture, la rafale de refus / le contenu disparu sont éprouvés : régression =
    pas de prolongation, l'expiration retire l'essai."""
    t = int(time.time())
    t0 = t - R.ESSAI_S - 60
    r = R.Regles()
    essai_d_indice(magasin, r, t0)
    jours = [evt(t0 - 86400 * j - i, f"habituel{i}.contenu.fr") for j in range(1, 4) for i in range(40)]
    charger(magasin, jours + [evt(t - 100 - i, "autre.contenu.fr") for i in range(150)])
    assert M._eprouver(regles_de(r)[PUB], [IP], magasin, REGLAGE, t) == "regression"
    M.tick(ETAT, r, magasin, classer, REGLAGE, t, indices=Index(lisible=False))
    assert regles_de(r)[PUB]["etat"] == "retire"


def test_b1_une_transition_remet_le_compteur_a_zero():
    r = R.Regles()
    rid = r.proposer("tv-banc", PUB, 50, "faible", 1)["id"]
    r.transiter(rid, "essai", "auto", "x", 2)
    r.prolonger_essai(rid, 3)
    r.prolonger_essai(rid, 4)
    assert r.get(rid)["prolongations"] == 2
    assert R.Regles.depuis_dict(r.vers_dict()).get(rid)["prolongations"] == 2
    r.transiter(rid, "confirme", "admin", "", 5)
    assert "prolongations" not in r.get(rid)
    for mauvais in (-1, True, "2", R.PROLONGATIONS_LUES_MAX + 1):
        with pytest.raises(R.ErreurRegle):
            R.valider_regle({"appareil": "tv-banc", "domaine": PUB, "etat": "essai", "prolongations": mauvais})


def test_f2_legitime_ailleurs_revient_a_la_decision_locale(magasin):
    """F2 : un indice freiné par un légitime ne bloque plus l'essai automatique ORDINAIRE (auto_essai, risque faible, catégorie
    non protégée) : la règle est alors locale (sans `indice`) et ne suit pas les indices."""
    t = int(time.time())
    pub = "7cd78.v.fwmrm.net"                                           # PUBLICITE localement (listes)
    charger(magasin, coupure(t - 600, pub))
    cl = dict(CLASSES, **{pub: "advertising"})
    reglage = M.Reglage(declencheurs=("fwmrm.net",), auto_essai=True)
    temoin = R.Regles()
    M.tick(ETAT, temoin, magasin, lambda d: cl.get(d, ""), reglage, t)
    attendu = regles_de(temoin).get(pub)
    r = R.Regles()
    M.tick(ETAT, r, magasin, lambda d: cl.get(d, ""), reglage, t, indices=indice(pub, legitimes={pub: {"gk1"}}))
    x = regles_de(r).get(pub)
    assert attendu["etat"] == "essai"                                   # sans indice : essai automatique local
    assert x["etat"] == "essai" and x["motif"] == "essai automatique" and "indice" not in x
    M.tick(ETAT, r, magasin, lambda d: cl.get(d, ""), reglage, t + 60, indices=indice(pub, legitimes={pub: {"gk1"}}))
    assert regles_de(r)[pub]["etat"] == "essai"                         # règle locale : jamais oubliée par les indices


def test_f7_motifs_nomment_les_box(magasin):
    t = int(time.time())
    charger(magasin, coupure(t - 600, PUB))
    r = R.Regles()
    M.tick(ETAT, r, magasin, classer, REGLAGE, t, indices=indice(PUB, par=("gk6", "gk2")))
    x = regles_de(r)[PUB]
    assert x["motif"] == "essai automatique, suggéré par gk2, gk6" and len(x["motif"]) <= 120
    noms = tuple(f"box-{i:02d}-" + "n" * 25 for i in range(8))
    assert len(M._motif_noms(M.PREFIXE_INDICE, list(noms))) <= 120
