# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3839 — mode tableau de bord (LAN sans jeton) : le verdict LAN de nginx est retransmis aux LECTURES du WAF et de
threatmesh, seulement quand le mode est actif. Constaté sur gk2 le 20/11 : sans lui, le WAF répondait 401 et les
cartes blocages/actions restaient vides depuis le LAN."""
# ruff: noqa: F811 — les fixtures pytest importées sont « redéfinies » par les paramètres des tests (faux positif).
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_defense_facade import faux, client, Substrat  # noqa: E402,F401  (fixtures réutilisées)
from api import defense  # noqa: E402

LAN = {"X-SecuBox-LAN": "1"}


def _entetes_waf(f):
    return [e for (s, _c, e) in f.appels if s == "waf"]


def test_verdict_lan_retransmis_quand_le_mode_est_actif(faux, client, monkeypatch):
    monkeypatch.setattr(defense, "mode_tableau_de_bord_actif", lambda: True)
    client.get("/defense/status", headers=LAN)
    vus = _entetes_waf(faux)
    assert vus and all(e.get("X-SecuBox-LAN") == "1" for e in vus)


def test_verdict_lan_ignore_quand_le_mode_est_inactif(faux, client, monkeypatch):
    monkeypatch.setattr(defense, "mode_tableau_de_bord_actif", lambda: False)
    client.get("/defense/status", headers=LAN)
    assert all("X-SecuBox-LAN" not in e for e in _entetes_waf(faux))


def test_valeur_autre_que_1_ignoree(faux, client, monkeypatch):
    monkeypatch.setattr(defense, "mode_tableau_de_bord_actif", lambda: True)
    client.get("/defense/status", headers={"X-SecuBox-LAN": "oui"})
    assert all("X-SecuBox-LAN" not in e for e in _entetes_waf(faux))


def test_le_ban_n_emprunte_jamais_le_verdict_lan():
    # POST /ban passe un porteur explicite, jamais _entetes_appelant : le mode LAN ne peut pas bannir.
    src = Path(defense.__file__).read_text(encoding="utf-8")
    appel = src[src.index('substrat.ecrire("waf", "/ban"'):]
    assert "_entetes_appelant" not in appel.split("\n", 1)[0]
    assert 'entetes={"Authorization": porteur}' in appel.split("\n", 1)[0]
