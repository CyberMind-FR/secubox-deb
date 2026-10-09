# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2188 : validation — pré-rapport sans secret, délai de grâce avec refus possible, confirmation d'opérateur liée au contenu."""
import json
import stat
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "secubox-premier-pas"))
from autoload_agent import moteur as M, validation as VA  # noqa: E402

T0 = 1_800_000_000
PLAN = M.Plan("lite", "auto", ["secubox-core", "secubox-ad-guard", "secubox-lite"])
REPONSES = {"box": {"nom": "client-042"}, "admin": {"mot_de_passe": "$argon2id$v=19$m=65536,t=3,p=4$c2FsdHNhbHQ$aGFzaGhhc2hoYXNoaGFzaA", "totp": "enroler"},
            "reseau": {"mode": "routeur", "domaine": "client042.secubox.in"}, "provision": {"mode": "auto", "jeton": "ref:/etc/secubox/secrets/autoload-jeton", "grace_min": 15}}


class Horloge:
    def __init__(self):
        self.t = float(T0)

    def __call__(self):
        return self.t

    def dormir(self, s):
        self.t += s


def valideur_auto(tmp_path, h, **kw):
    args = dict(grace_min=15, publier=lambda r: None, refuse=lambda e: False, dossier=tmp_path, horloge=h, dormir=h.dormir, reponses=REPONSES)
    args.update(kw)
    return VA.valideur_auto(**args)


def test_le_pre_rapport_dit_ce_qui_va_arriver_sans_aucun_secret():
    r = VA.construire(PLAN, REPONSES, T0)
    assert r["profil"] == "lite" and "secubox-ad-guard" in r["paquets"] and r["comptes"] == ["admin"] and r["reseau"]["domaine"] == "client042.secubox.in"
    texte = json.dumps(r)
    assert "argon2" not in texte and "autoload-jeton" not in texte                    # ni l'empreinte du mot de passe ni le nom du fichier du jeton
    assert r["secrets"] == ["jeton", "mot_de_passe"]                                  # on dit seulement QU'il y en a


def test_l_empreinte_change_si_le_contenu_change():
    a = VA.construire(PLAN, REPONSES, 1)
    b = VA.construire(M.Plan("lite", "auto", ["secubox-core"]), REPONSES, 1)
    assert VA.empreinte(a) != VA.empreinte(b) and VA.empreinte(a) == VA.empreinte(VA.construire(PLAN, REPONSES, 1))


def test_auto_applique_apres_le_delai_de_grace_quand_personne_ne_refuse(tmp_path):
    h, publies = Horloge(), []
    assert valideur_auto(tmp_path, h, publier=publies.append)(PLAN) is True
    assert 15 * 60 <= h.t - T0 <= 15 * 60 + 60 and len(publies) == 1
    fichier = next(tmp_path.glob("prerapport-*.json"))
    assert stat.S_IMODE(fichier.stat().st_mode) == 0o600 and json.loads(fichier.read_text())["profil"] == "lite"


def test_auto_un_refus_pendant_la_grace_arrete_tout(tmp_path):
    h = Horloge()
    appels = []

    def refuse(empreinte):
        appels.append(h.t)
        return len(appels) >= 3
    assert valideur_auto(tmp_path, h, refuse=refuse)(PLAN) is False
    assert h.t - T0 < 15 * 60                                                        # arrêté avant la fin du délai


def test_auto_ferme_par_defaut_si_le_pre_rapport_n_a_pas_pu_etre_publie(tmp_path):
    def echec(r):
        raise OSError("réseau")
    assert valideur_auto(tmp_path, Horloge(), publier=echec)(PLAN) is False          # personne ne pourrait refuser : on n'applique pas


def test_auto_si_la_consultation_du_refus_echoue_on_n_applique_pas(tmp_path):
    def casse(e):
        raise OSError("réseau")
    assert valideur_auto(tmp_path, Horloge(), refuse=casse)(PLAN) is False


def test_grace_zero_applique_aussitot_mais_publie(tmp_path):
    h, publies = Horloge(), []
    assert valideur_auto(tmp_path, h, grace_min=0, publier=publies.append)(PLAN) is True
    assert h.t == T0 and len(publies) == 1


@pytest.mark.parametrize("grace", [-1, 1441, "15", True, None])
def test_grace_invalide_refusee(tmp_path, grace):
    with pytest.raises(ValueError):
        valideur_auto(tmp_path, Horloge(), grace_min=grace)


def test_manuel_exige_la_confirmation_de_CE_pre_rapport(tmp_path):
    h = Horloge()
    vus = []

    def lire():
        vus.append(1)
        return VA.empreinte(VA.construire(PLAN, REPONSES, T0)) if len(vus) >= 2 else None
    v = VA.valideur_manuel(lire_confirmation=lire, attente_max_s=600, dossier=tmp_path, horloge=h, dormir=h.dormir, reponses=REPONSES)
    assert v(PLAN) is True


def test_manuel_une_confirmation_d_un_autre_plan_est_refusee(tmp_path):
    h = Horloge()
    autre = VA.empreinte(VA.construire(M.Plan("full", "one-shot", ["x"]), REPONSES, T0))
    v = VA.valideur_manuel(lire_confirmation=lambda: autre, attente_max_s=120, dossier=tmp_path, horloge=h, dormir=h.dormir, reponses=REPONSES)
    assert v(PLAN) is False                                                          # ne valide pas un autre plan, puis expire


def test_manuel_expire_sans_confirmation(tmp_path):
    h = Horloge()
    v = VA.valideur_manuel(lire_confirmation=lambda: None, attente_max_s=300, dossier=tmp_path, horloge=h, dormir=h.dormir, reponses=REPONSES)
    assert v(PLAN) is False and h.t - T0 >= 300


def test_le_choix_suit_le_mode_du_fichier_de_reponses(tmp_path):
    h = Horloge()
    commun = dict(dossier=tmp_path, publier=lambda r: None, refuse=lambda e: False, lire_confirmation=lambda: None, horloge=h, dormir=h.dormir)
    assert VA.pour_mode("auto", REPONSES, **commun)(PLAN) is True
    assert VA.pour_mode("one-shot", REPONSES, **commun)(PLAN) is False              # personne ne confirme
    with pytest.raises(ValueError):
        VA.pour_mode("autre", REPONSES, **commun)
