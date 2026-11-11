# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""MirrorNet 4c (#3661) : l'export donne à l'espace les abonnés des jeux qu'on lui confie, et à l'abonné les espaces
qui gardent ses jeux — rien de plus."""
from annuaire import mirrornet_export as MX
from annuaire import verbs as V
from tests.test_mirrornet_cycle_3647 import _membre, j  # noqa: F401 (fixture)


def _subs(export):
    return {e["payload"]["subscription_id"] for e in export["entrees"] if e["op"] == "service_subscribe"}


def test_export_relais_et_repliques(j):  # noqa: F811
    pp, _, dp = _membre(j)          # producteur
    pg, _, dg = _membre(j)          # gardien de l'espace
    pa, _, da = _membre(j)          # abonné du jeu
    px, _, dx = _membre(j)          # tiers sans rapport
    jeu = V.offer_service(j, pp, dp, name="Jeu", kind="dataset", endpoint="mesh:j", approval_mode="auto")
    autre = V.offer_service(j, pp, dp, name="Autre", kind="dataset", endpoint="mesh:a", approval_mode="auto")
    esp = V.offer_service(j, pg, dg, name="Espace", kind="espace", endpoint="mesh:e", approval_mode="auto")
    s_esp = V.subscribe(j, pp, dp, esp.service_id, jeux=[jeu.service_id])
    s_ab = V.subscribe(j, pa, da, jeu.service_id)
    s_autre = V.subscribe(j, px, dx, autre.service_id)           # jeu NON confié à l'espace
    # Un tiers qui « confie » le jeu d'un autre : ignoré (le producteur doit signer).
    faux = V.subscribe(j, px, dx, esp.service_id, jeux=[jeu.service_id])
    vu_g = _subs(MX.construire(j, dg, {}))
    assert s_ab.subscription_id in vu_g and s_autre.subscription_id not in vu_g
    vu_a = _subs(MX.construire(j, da, {}))
    assert s_esp.subscription_id in vu_a and faux.subscription_id not in vu_a
    vu_x = _subs(MX.construire(j, dx, {}))
    assert s_ab.subscription_id not in vu_x and s_esp.subscription_id not in vu_x


def test_cache_d_export_expire(tmp_path, monkeypatch):
    """Banc #3661 : même hauteur, l'export est quand même recalculé une fois le cache expiré."""
    monkeypatch.setenv("ANNUAIRE_DIR_SYNC", "0")
    from api import main as M
    M._journal = None
    M._DB_PATH = str(tmp_path / "journal.db")
    M._EXPORT_CACHE.update(hauteur=None, donnees=None, le=0.0)
    monkeypatch.setattr(M, "MIRRORNET_EXPORT", tmp_path / "mirrornet-export.json")
    appels = []
    vrai = MX.construire
    monkeypatch.setattr(MX, "construire", lambda *a, **k: appels.append(1) or vrai(*a, **k))
    M._exporter_mirrornet()
    M._exporter_mirrornet()
    assert len(appels) == 1                                   # même hauteur, cache frais : pas de recalcul
    M._EXPORT_CACHE["le"] -= M.EXPORT_CACHE_S + 1
    M._exporter_mirrornet()
    assert len(appels) == 2
