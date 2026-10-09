# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2190 : registre côté infrastructure — reprise d'une réclamation, abonnement avec échéance, progression, pré-rapports."""
import hashlib
import json
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from autoload import jetons as J  # noqa: E402

CLE_A, CLE_B = "A" * 43 + "=", "B" * 43 + "="
T0 = 1_800_000_000


class Horloge:
    def __init__(self, t=T0):
        self.t = t

    def __call__(self):
        return self.t


@pytest.fixture
def reg(tmp_path):
    h = Horloge()
    r = J.Registre(tmp_path / "j.db", tmp_path / "audit.log", horloge=h)
    r.h = h
    return r


def pre_rapport(**kw):
    corps = {"horodatage": T0, "box": "client-042", "profil": "lite", "mode": "auto", "paquets": ["secubox-core"], "comptes": ["admin"],
             "reseau": {"mode": "routeur", "domaine": "c.secubox.in"}, "secrets": ["jeton"]}
    corps.update(kw)
    corps["empreinte"] = hashlib.sha256(json.dumps({k: v for k, v in corps.items() if k != "empreinte"}, sort_keys=True, ensure_ascii=False,
                                                   separators=(",", ":")).encode()).hexdigest()
    return corps


# ── reprise ──────────────────────────────────────────────────────────────────────────────────────────────────
def test_la_meme_box_peut_reprendre_sa_reclamation_apres_une_coupure(reg):
    e = reg.emettre("c1", "lite")
    r1 = reg.reclamer(e.valeur, CLE_A)
    r2 = reg.reclamer(e.valeur, CLE_A)                                  # réponse perdue : la box rejoue avec la MÊME clé
    assert (r2.id, r2.client) == (r1.id, "c1")
    with pytest.raises(J.JetonRefuse):
        reg.reclamer(e.valeur, CLE_B)                                   # une autre clé, jamais
    assert [l["action"] for l in [json.loads(x) for x in reg.audit_chemin.read_text().splitlines()]].count("jeton-repris") == 1


def test_la_reprise_ne_vaut_pas_pour_un_jeton_revoque_ou_un_abonnement_suspendu(reg):
    e = reg.emettre("c1", "lite")
    reg.reclamer(e.valeur, CLE_A)
    reg.fixer_abonnement("c1", "suspendu")
    with pytest.raises(J.JetonRefuse):
        reg.reclamer(e.valeur, CLE_A)
    reg.fixer_abonnement("c1", "actif")
    reg.revoquer(e.id, "x")
    with pytest.raises(J.JetonRefuse):
        reg.reclamer(e.valeur, CLE_A)


# ── abonnement avec échéance et formule ───────────────────────────────────────────────────────────────────
def test_abonnement_a_echeance(reg):
    e = reg.emettre("c1", "lite")
    reg.fixer_abonnement("c1", "actif", expire_le=T0 + 3600, formule="pme_12m")
    reg.reclamer(e.valeur, CLE_A)
    assert reg.livraison_autorisee(CLE_A) is True
    reg.h.t += 3601
    assert reg.livraison_autorisee(CLE_A) is False                       # échu : plus de nouvelle livraison
    assert reg.lister()[0]["abonnement"] == "echu" and reg.lister()[0]["formule"] == "pme_12m"
    reg.fixer_abonnement("c1", "actif", expire_le=reg.h.t + 86400)         # renouvelé
    assert reg.livraison_autorisee(CLE_A) is True


def test_ajouter_mois_est_calendaire():
    t = int(time.mktime(time.strptime("2026-01-31", "%Y-%m-%d")))
    assert time.strftime("%Y-%m-%d", time.gmtime(J.ajouter_mois(t, 1)))[:7] == "2026-03" or time.strftime("%Y-%m-%d", time.gmtime(J.ajouter_mois(t, 1))) in ("2026-02-28", "2026-02-27")
    a = int(time.mktime(time.strptime("2026-10-10", "%Y-%m-%d")))
    assert time.strftime("%Y-%m-%d", time.gmtime(J.ajouter_mois(a, 12)))[:4] == "2027"
    for n in (0, -1, 121, True):
        with pytest.raises(ValueError):
            J.ajouter_mois(a, n)


@pytest.mark.parametrize("formule", ["", "Pme 12", "a" * 31, "x;y", None.__class__])
def test_formule_invalide_refusee(reg, formule):
    with pytest.raises(ValueError):
        reg.fixer_abonnement("c1", "actif", formule=formule)


# ── progression et statut des box ─────────────────────────────────────────────────────────────────────────
def test_statut_et_progression_suivent_la_vie_de_la_box(reg):
    reg.emettre("c1", "lite")
    b = reg.boxes()[0]
    assert (b["statut"], b["progression"]) == ("en attente", 0)
    e = reg.emettre("c2", "isp")
    reg.reclamer(e.valeur, CLE_A)
    b = [x for x in reg.boxes() if x["client"] == "c2"][0]
    assert (b["statut"], b["progression"]) == ("préparation", 0)
    reg.noter_progression(CLE_A, "installation", faites=6, total=8)
    b = [x for x in reg.boxes() if x["client"] == "c2"][0]
    assert (b["statut"], b["progression"], b["etape"]) == ("en cours", 75, "installation")
    reg.noter_progression(CLE_A, "application", faites=8, total=8, termine=True)
    b = [x for x in reg.boxes() if x["client"] == "c2"][0]
    assert (b["statut"], b["progression"]) == ("terminé", 100)


@pytest.mark.parametrize("etape,faites,total", [("x" * 41, 1, 8), ("ok", -1, 8), ("ok", 9, 8), ("ok", 1, 0), ("ok", 1, 500), ("ok", True, 8), ("é;", 1, 8)])
def test_progression_hors_bornes_refusee(reg, etape, faites, total):
    reg.reclamer(reg.emettre("c1", "lite").valeur, CLE_A)
    with pytest.raises(ValueError):
        reg.noter_progression(CLE_A, etape, faites=faites, total=total)


def test_progression_d_une_cle_inconnue_ou_non_reclamee_refusee(reg):
    with pytest.raises(ValueError):
        reg.noter_progression(CLE_B, "plan", faites=1, total=8)


# ── pré-rapports ─────────────────────────────────────────────────────────────────────────────────────────
def test_pre_rapport_recu_consultable_et_refusable(reg):
    reg.reclamer(reg.emettre("c1", "lite").valeur, CLE_A)
    p = pre_rapport()
    reg.recevoir_prerapport(CLE_A, p)
    assert reg.prerapport_refuse(p["empreinte"]) is False
    assert reg.prerapports()[0]["empreinte"] == p["empreinte"] and reg.prerapports()[0]["client"] == "c1"
    reg.refuser_prerapport(p["empreinte"], "profil inattendu")
    assert reg.prerapport_refuse(p["empreinte"]) is True
    assert any(json.loads(l)["action"] == "prerapport-refuse" for l in reg.audit_chemin.read_text().splitlines())


def test_pre_rapport_dont_l_empreinte_ne_correspond_pas_refuse(reg):
    reg.reclamer(reg.emettre("c1", "lite").valeur, CLE_A)
    p = pre_rapport()
    p["paquets"] = ["secubox-core", "evil"]                              # contenu modifié, empreinte annoncée inchangée
    with pytest.raises(ValueError):
        reg.recevoir_prerapport(CLE_A, p)


def test_pre_rapport_d_une_cle_inconnue_ou_trop_gros_refuse(reg):
    with pytest.raises(ValueError):
        reg.recevoir_prerapport(CLE_B, pre_rapport())
    reg.reclamer(reg.emettre("c1", "lite").valeur, CLE_A)
    with pytest.raises(ValueError):
        reg.recevoir_prerapport(CLE_A, pre_rapport(paquets=["p" * 20] * 10000))


def test_la_refus_d_un_pre_rapport_inconnu_est_une_erreur(reg):
    with pytest.raises(ValueError):
        reg.refuser_prerapport("0" * 64, "x")
    assert reg.prerapport_refuse("0" * 64) is False
