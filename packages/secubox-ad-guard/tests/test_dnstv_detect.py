# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
from api import dnstv_detect as D

T0 = 1_800_000_000
DECLENCHEURS = ("fwmrm.net",)
CLASSES = {"ad.doubleclick.net": "advertising", "7cd77.v.fwmrm.net": "advertising"}


def declencheur(d):
    return any(d == s or d.endswith("." + s) for s in DECLENCHEURS)


def classer(d):
    return CLASSES.get(d, "")


def ev(ts, d, dec="ALLOWED"):
    return {"ts": ts, "domaine": d, "decision": dec}


def coupure(t, noms):
    """Une coupure : le serveur d'insertion puis les noms de la pub dans les 60 s."""
    return [ev(t, "7cd77.v.fwmrm.net")] + [ev(t + 2 + i, n) for i, n in enumerate(noms)]


def lecture(t):
    return [ev(t + i * 20, d) for i, d in enumerate(["cloudreplay.ftven.fr", "k7.ftven.fr", "hdfauth.ftven.fr"])]


def noms(cands):
    return {c.domaine: c for c in cands}


def test_apprend_ce_qui_n_apparait_que_pendant_les_coupures():
    evts = lecture(T0) + coupure(T0 + 300, ["videos-pub.ftv-publicite.fr", "cloudreplay.ftven.fr"]) + lecture(T0 + 500) \
        + coupure(T0 + 900, ["videos-pub.ftv-publicite.fr", "k7.ftven.fr"])
    c = noms(D.detecter(sorted(evts, key=lambda e: e["ts"]), declencheur, classer, set()))
    assert "videos-pub.ftv-publicite.fr" in c                       # vu dans 2 coupures, jamais en lecture
    assert "cloudreplay.ftven.fr" not in c and "k7.ftven.fr" not in c  # le contenu est aussi demandé hors coupure
    assert c["videos-pub.ftv-publicite.fr"].coupures == 2


def test_un_seul_passage_ne_suffit_pas_pour_un_inconnu():
    evts = lecture(T0) + coupure(T0 + 300, ["videos-pub.ftv-publicite.fr"])
    assert "videos-pub.ftv-publicite.fr" not in noms(D.detecter(evts, declencheur, classer, set()))


def test_un_domaine_classe_publicitaire_est_propose_des_la_premiere_coupure():
    evts = lecture(T0) + coupure(T0 + 300, ["ad.doubleclick.net"])
    c = noms(D.detecter(evts, declencheur, classer, set()))
    assert c["ad.doubleclick.net"].score > 50 and c["ad.doubleclick.net"].risque == "faible"


def test_le_serveur_d_insertion_est_propose_et_signale_partage_s_il_sert_aussi_hors_coupure():
    # le serveur d'insertion est aussi demandé 90 s après le début de la coupure, donc hors de sa fenêtre de 60 s
    evts = lecture(T0) + [ev(T0 + 5, "7cd77.v.fwmrm.net"), ev(T0 + 95, "7cd77.v.fwmrm.net")] + coupure(T0 + 600, [])
    c = noms(D.detecter(sorted(evts, key=lambda e: e["ts"]), declencheur, classer, set()))
    assert c["7cd77.v.fwmrm.net"].risque == "partage"


def test_liste_noire_jamais_proposee_meme_sous_domaine():
    bad = ["play.googleapis.com", "www.gstatic.com", "configuration.ls.apple.com", "s3.amazonaws.com"]
    evts = coupure(T0, bad) + coupure(T0 + 900, bad)
    c = noms(D.detecter(evts, declencheur, classer, set()))
    assert not (set(bad) & set(c))
    assert all(D.est_liste_noire(b) for b in bad)


def test_exclus_ne_sont_pas_reproposes():
    evts = coupure(T0, ["ad.doubleclick.net"]) + coupure(T0 + 900, ["ad.doubleclick.net"])
    assert "ad.doubleclick.net" not in noms(D.detecter(evts, declencheur, classer, {"ad.doubleclick.net"}))


def test_noms_variables_regroupes_sous_le_parent():
    var = ["r1---sn-aaa.c.2mdn.net", "r5---sn-bbb.c.2mdn.net", "r2---sn-ccc.c.2mdn.net"]
    evts = coupure(T0, var) + coupure(T0 + 900, var)
    c = noms(D.detecter(evts, declencheur, classer, set()))
    assert "c.2mdn.net" in c and c["c.2mdn.net"].risque == "variable"
    assert not any(n.startswith("r1---") for n in c)


def test_evenements_hostiles_ignores():
    evts = coupure(T0, ['x"; reboot', "A B.com", "../etc"]) + coupure(T0 + 900, ['x"; reboot', "A B.com", "../etc"])
    # seul le serveur d'insertion (classé publicitaire) peut ressortir ; aucun nom hostile n'est jamais proposé
    assert {c.domaine for c in D.detecter(evts, declencheur, classer, set())} <= {"7cd77.v.fwmrm.net"}


def test_pas_de_declencheur_pas_de_candidat():
    assert D.detecter(lecture(T0), declencheur, classer, set()) == []


def test_refus_deja_appliques_ne_comptent_pas_comme_vus():
    """Un nom déjà refusé (BLOCKED) pendant l'essai ne doit pas être reproposé ni compté comme du contenu hors coupure."""
    evts = coupure(T0, []) + [ev(T0 + 3, "ad.doubleclick.net", "BLOCKED")]
    assert "ad.doubleclick.net" not in noms(D.detecter(evts, declencheur, classer, set()))   # refusé = déjà géré : ni vu, ni proposé
