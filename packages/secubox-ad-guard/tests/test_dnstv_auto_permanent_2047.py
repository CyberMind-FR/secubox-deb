# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2047 — détection automatique permanente : confirmation sur délais, déclencheurs intelligents."""
import time

import pytest

from api import dnstv, dnstv_auto as M, dnstv_regles as R

IP = "192.168.1.95"
ETAT = {"actif": True, "clients": [{"ip": IP, "nom": "TV banc", "mode": "auto"}]}
CLASSES = {"7cd77.v.fwmrm.net": "advertising", "ads.exemple-pub.net": "advertising", "tracker.exemple-pub.net": "tracking"}


def classer(d):
    return CLASSES.get(d, "")


def evt(ts, d, decision="ALLOWED"):
    return dnstv.Evenement(ts, IP, d, "A", "NXDOMAIN" if decision == "BLOCKED" else "NOERROR", decision)


@pytest.fixture
def magasin(tmp_path):
    return dnstv.Magasin(tmp_path / "m.db")


def charger(magasin, evts):
    magasin.ajouter([(e, "") for e in evts])


def en_essai(regles, domaine, depuis):
    rid = regles.proposer("tv-banc", domaine, 50, "faible", depuis)["id"]
    regles.transiter(rid, "essai", "auto", "essai automatique", depuis)
    return rid


def activite(t, n=150):
    """Du contenu habituel : l'appareil est actif, sans refus."""
    return [evt(t - i * 5, "api.contenu-habituel.fr") for i in range(n)]


# ── confirmation automatique sur délais ───────────────────────────────────────────────────────────────

def test_essai_sans_regression_est_confirme_a_l_echeance(magasin):
    t = int(time.time())
    r = R.Regles()
    rid = en_essai(r, "ad.example.com", t - R.ESSAI_S - 60)
    charger(magasin, activite(t - 100))
    res = M.tick(ETAT, r, magasin, classer, M.Reglage(confirmation_auto=True), t)
    assert r.get(rid)["etat"] == "confirme"
    assert r.get(rid)["historique"][-1]["origine"] == "auto"
    assert res["applique"] is False                      # essai et confirmé bloquent tous deux : Unbound ne change pas


def test_sans_confirmation_auto_l_essai_expire_comme_avant(magasin):
    t = int(time.time())
    r = R.Regles()
    rid = en_essai(r, "ad.example.com", t - R.ESSAI_S - 60)
    charger(magasin, activite(t - 100))
    M.tick(ETAT, r, magasin, classer, M.Reglage(), t)
    assert r.get(rid)["etat"] == "retire"                # défaut inchangé : validation humaine


def test_appareil_peu_actif_prolonge_l_essai_au_lieu_de_confirmer_a_l_aveugle(magasin):
    t = int(time.time())
    r = R.Regles()
    rid = en_essai(r, "ad.example.com", t - R.ESSAI_S - 60)
    charger(magasin, activite(t - 100, n=5))             # TV éteinte presque tout le temps : règle jamais éprouvée
    M.tick(ETAT, r, magasin, classer, M.Reglage(confirmation_auto=True), t)
    p = r.get(rid)
    assert p["etat"] == "essai" and p["fin_essai"] > t   # prolongé d'une période, ni retiré ni confirmé


def test_rafale_de_refus_empeche_la_confirmation(magasin):
    t = int(time.time())
    r = R.Regles()
    rid = en_essai(r, "ad.example.com", t - R.ESSAI_S - 60)
    refus = [evt(t - m * 60 - s, "ad.example.com", "BLOCKED") for m in range(6) for s in range(0, 60, 1)]
    charger(magasin, activite(t - 100) + refus)
    M.tick(ETAT, r, magasin, classer, M.Reglage(confirmation_auto=True, seuil_refus_min=30, duree_rafale_min=5), t)
    assert r.get(rid)["etat"] == "retire"                # la régression gagne


# ── déclencheurs intelligents ──────────────────────────────────────────────────────────────────────────

def coupure_pub(t):
    # un hôte de pub connu (déjà BLOQUÉ) ouvre la coupure ; un hôte nouveau suit
    return [evt(t, "ads.exemple-pub.net", "BLOCKED"), evt(t + 3, "nouveau-serveur-pub.exemple.fr")]


def test_un_hote_de_pub_bloque_ouvre_la_fenetre_de_detection(magasin):
    t = int(time.time())
    charger(magasin, coupure_pub(t - 3000) + coupure_pub(t - 1500))
    r = R.Regles()
    M.tick(ETAT, r, magasin, classer, M.Reglage(declencheurs=("fwmrm.net",), declencheurs_pub=True), t)
    assert "nouveau-serveur-pub.exemple.fr" in {x["domaine"] for x in r.liste()}


def test_sans_declencheurs_pub_comportement_inchange(magasin):
    t = int(time.time())
    charger(magasin, coupure_pub(t - 3000) + coupure_pub(t - 1500))
    r = R.Regles()
    M.tick(ETAT, r, magasin, classer, M.Reglage(declencheurs=("fwmrm.net",)), t)
    assert r.liste() == []


def test_le_reglage_se_lit_dans_le_toml(tmp_path):
    f = tmp_path / "ad-guard.toml"
    f.write_text("[adblock_tv_auto]\nconfirmation_auto = true\ndeclencheurs_pub = true\n")
    rg = M.reglage_depuis({}, f)
    assert rg.confirmation_auto is True and rg.declencheurs_pub is True
    assert M.reglage_depuis({}, tmp_path / "absent.toml").confirmation_auto is False


# ── un domaine confirmé ailleurs par l'administrateur entre à l'essai (constaté sur gk2 : pub Canal+) ─────────────────

ETAT3 = {"actif": True, "clients": [{"ip": "192.168.1.95", "nom": "TV a", "mode": "auto"},
                                     {"ip": "192.168.1.96", "nom": "TV b", "mode": "auto"},
                                     {"ip": "192.168.1.97", "nom": "TV c", "mode": "auto"}]}


def confirme_par_admin(regles, appareil, domaine, t):
    rid = regles.proposer(appareil, domaine, 50, "faible", t - 100, origine="admin")["id"]
    regles.transiter(rid, "essai", "admin", "", t - 100)
    regles.transiter(rid, "confirme", "admin", "ok", t - 90)


def test_un_candidat_agrege_entre_a_l_essai_si_l_essai_automatique_est_actif(magasin):
    t = int(time.time())
    r = R.Regles()
    for app in ("tv-a", "tv-b"):
        confirme_par_admin(r, app, "ads-canalplus.akamaized.net", t)
    M.tick(ETAT3, r, magasin, classer, M.Reglage(auto_essai=True), t)
    c = [x for x in r.liste() if x["appareil"] == "tv-c"]
    assert [x["etat"] for x in c] == ["essai"]
    assert c[0]["historique"][-1]["origine"] == "auto"


def test_un_candidat_agrege_reste_candidat_sans_essai_automatique(magasin):
    t = int(time.time())
    r = R.Regles()
    for app in ("tv-a", "tv-b"):
        confirme_par_admin(r, app, "ads-canalplus.akamaized.net", t)
    M.tick(ETAT3, r, magasin, classer, M.Reglage(), t)
    assert [x["etat"] for x in r.liste() if x["appareil"] == "tv-c"] == ["candidat"]


def test_un_candidat_agrege_deja_la_depuis_un_passage_precedent_est_aussi_promu(magasin):
    t = int(time.time())
    r = R.Regles()
    for app in ("tv-a", "tv-b"):
        confirme_par_admin(r, app, "vizchoice.viznet.tv", t)
    M.tick(ETAT3, r, magasin, classer, M.Reglage(), t)                      # créé en candidat (essai auto inactif)
    M.tick(ETAT3, r, magasin, classer, M.Reglage(auto_essai=True), t + 60)  # puis l'essai auto est activé
    assert [x["etat"] for x in r.liste() if x["appareil"] == "tv-c"] == ["essai"]


def test_un_candidat_a_risque_non_faible_n_est_pas_promu(magasin):
    t = int(time.time())
    r = R.Regles()
    r.proposer("tv-c", "partage.example.com", 50, "partage", t, origine="auto", motif="confirmé sur 2 autres appareils")
    M.tick(ETAT3, r, magasin, classer, M.Reglage(auto_essai=True), t + 60)
    assert [x["etat"] for x in r.liste() if x["appareil"] == "tv-c"] == ["candidat"]
