# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3839 — SADE ACTIVE : mode ouvert (aggressive reste fermé), réclamation par mode, compteur de bans automatiques,
approbation manuelle ouverte en REACTIVE et ACTIVE."""
# ruff: noqa: F811 — les fixtures pytest importées sont « redéfinies » par les paramètres des tests (faux positif).
import os
import sqlite3
import sys
from contextlib import closing
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_defense_approbation import isole, client, P1, ADMIN  # noqa: E402,F401  (fixtures réutilisées)
from api import defense_etat  # noqa: E402


@pytest.fixture
def etat():
    defense_etat.mode_courant()  # amorce la base
    return defense_etat


def test_active_ouvert_aggressive_ferme(etat):
    defense_etat.changer_mode("active", "admin")
    assert defense_etat.mode_courant() == "active"
    with pytest.raises(PermissionError):
        defense_etat.changer_mode("aggressive", "admin")


def test_reclamer_respecte_les_modes(etat):
    defense_etat.changer_mode("active", "admin")
    with pytest.raises(defense_etat.ModeRefuse):
        defense_etat.reclamer("a" * 64, "ACT-1", "ban", "203.0.113.5", 70, 3600, "x", "en_cours", "sade-test")
    g = defense_etat.reclamer("a" * 64, "ACT-1", "ban", "203.0.113.5", 70, 3600, "sade-auto", "en_cours",
                              "sade-auto-demande", modes=("active",))
    assert g == 1


def _ts(il_y_a_s):
    return (datetime.now(timezone.utc) - timedelta(seconds=il_y_a_s)).strftime("%Y-%m-%dT%H:%M:%SZ")


def _inserer(emp, cible, par, etat_d, il_y_a_s):
    with closing(sqlite3.connect(os.environ["SECUBOX_SOC_DEFENSE_DB"])) as db, db:
        db.execute("INSERT INTO decisions(empreinte, generation, menace_id, cible, geste, score, ttl_s, etat, "
                   "demande_ts, tranche_ts, par) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                   (emp, 1, "ACT-x", cible, "ban", 70, 3600, etat_d, _ts(il_y_a_s), None, par))


def test_bans_auto_compte_les_adresses_de_l_heure(etat):
    _inserer("1" * 64, "203.0.113.1", "sade-auto", "applique", 60)
    _inserer("2" * 64, "203.0.113.2,203.0.113.3", "sade-auto", "en_cours", 120)
    _inserer("3" * 64, "203.0.113.4", "admin", "applique", 60)            # un administrateur : pas compté
    _inserer("4" * 64, "203.0.113.5", "sade-auto", "applique", 7200)      # hors fenêtre
    _inserer("5" * 64, "203.0.113.6", "sade-auto", "refuse", 60)          # refusée : pas appliquée
    assert defense_etat.bans_auto_depuis(3600) == 3


def test_bans_auto_zero_sans_decision(etat):
    assert defense_etat.bans_auto_depuis(3600) == 0


@pytest.mark.parametrize("mode,ok", [("reactive", True), ("active", True), ("observe", False)])
def test_approbation_manuelle_selon_le_mode(client, mode, ok):
    if mode != "observe":
        defense_etat.changer_mode(mode, "test")
    r = client.post("/defense/approve", json={"empreinte": P1, "simuler": True}, headers=ADMIN)
    if ok:
        assert r.status_code == 200 and r.json()["etat"] == "simule"
    else:
        assert r.status_code == 409 and r.json()["cause"] == "mode"
