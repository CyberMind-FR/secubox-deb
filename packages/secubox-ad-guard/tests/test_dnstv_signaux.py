# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
from api import dnstv_signaux as S

T = 1_800_000_000


def refus(d, par_min, minutes, fin=T):
    """`par_min` refus par minute pendant `minutes` minutes, se terminant à `fin`."""
    out = []
    for m in range(minutes):
        for k in range(par_min):
            out.append({"ts": fin - m * 60 - (k * 60) // par_min, "domaine": d, "decision": "BLOCKED"})   # répartis dans la minute
    return out


def test_le_comportement_normal_mesure_n_est_pas_une_rafale():
    """Mesuré le 2026-10-03 : la TV, lecture NORMALE, redemande un domaine refusé ~10 fois par minute."""
    assert S.rafale(refus("videos-pub.ftv-publicite.fr", 10, 10), {"videos-pub.ftv-publicite.fr"}, T) == []


def test_rafale_soutenue_detectee():
    assert S.rafale(refus("ad.example.com", 80, 6), {"ad.example.com"}, T) == ["ad.example.com"]


def test_rafale_courte_ignoree():
    assert S.rafale(refus("ad.example.com", 80, 2), {"ad.example.com"}, T) == []


def test_rafale_sur_un_domaine_non_gere_ignoree():
    assert S.rafale(refus("autre.example.com", 80, 6), {"ad.example.com"}, T) == []


def test_contenu_disparu_quand_l_appareil_reste_actif():
    jours = {"cloudreplay.ftven.fr": 5, "k7.ftven.fr": 4, "rare.example.com": 1}
    assert S.contenu_disparu(jours, vus_depuis={"k7.ftven.fr"}, requetes_depuis=500) == ["cloudreplay.ftven.fr"]


def test_appareil_inactif_ne_retire_rien():
    """TV éteinte : aucune requête, donc aucun contenu « disparu »."""
    jours = {"cloudreplay.ftven.fr": 5}
    assert S.contenu_disparu(jours, vus_depuis=set(), requetes_depuis=0) == []
    assert S.contenu_disparu(jours, vus_depuis=set(), requetes_depuis=S.MIN_REQUETES_ACTIF - 1) == []


def test_contenu_present_ne_signale_rien():
    assert S.contenu_disparu({"cloudreplay.ftven.fr": 5}, {"cloudreplay.ftven.fr"}, 500) == []
