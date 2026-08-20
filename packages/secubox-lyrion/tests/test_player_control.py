# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# See LICENCE-CMSD-1.0.md for terms.

"""Pilotage des lecteurs (#1071) : les verbes de contrôle traduisent en la BONNE
commande LMS JSON-RPC, adressée au bon lecteur, et les entrées invalides sont
refusées AVANT tout appel à LMS.

On appelle les fonctions d'endpoint directement (ce sont de simples fonctions)
en remplaçant `_lms_rpc` par une doublure — pas de socket, pas de TestClient.
"""
import sys
from pathlib import Path

import pytest

_pkg = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_pkg / "api"))
sys.path.insert(0, str(_pkg.parents[1] / "common"))  # secubox_core

import main  # noqa: E402
from fastapi import HTTPException  # noqa: E402


@pytest.fixture
def appels(monkeypatch):
    """Enregistre chaque slim.request au lieu de l'envoyer à LMS."""
    faits = []

    def faux_rpc(player, command, timeout=5.0):
        faits.append((player, command))
        return {}

    monkeypatch.setattr(main, "_lms_rpc", faux_rpc)
    return faits


def test_actions_simples_traduisent_en_commande_lms(appels):
    assert main.player_action("aa:bb:cc", "play")["ok"] is True
    main.player_action("aa:bb:cc", "next")
    main.player_action("aa:bb:cc", "unsync")
    assert appels == [
        ("aa:bb:cc", ["play"]),
        ("aa:bb:cc", ["playlist", "index", "+1"]),
        ("aa:bb:cc", ["sync", "-"]),
    ]


def test_action_inconnue_refusee_sans_appel_lms(appels):
    with pytest.raises(HTTPException) as e:
        main.player_action("p1", "supprime-tout")
    assert e.value.status_code == 400
    assert appels == []  # rien n'est parti vers LMS


def test_pid_vide_refuse(appels):
    with pytest.raises(HTTPException) as e:
        main.player_action("   ", "play")
    assert e.value.status_code == 400
    assert appels == []


def test_volume_borne_et_typé(appels):
    assert main.player_volume("p1", {"level": 55})["volume"] == 55
    assert appels[-1] == ("p1", ["mixer", "volume", "55"])
    for mauvais in ({"level": 200}, {"level": -1}, {"level": "fort"}, {}):
        with pytest.raises(HTTPException) as e:
            main.player_volume("p1", mauvais)
        assert e.value.status_code == 400
    assert len(appels) == 1  # seul le volume valide est parti


def test_power_on_off(appels):
    main.player_power("p1", {"on": False})
    assert appels[-1] == ("p1", ["power", "0"])
    main.player_power("p1", {"on": True})
    assert appels[-1] == ("p1", ["power", "1"])
    main.player_power("p1", None)  # défaut = allumer
    assert appels[-1] == ("p1", ["power", "1"])


def test_sync_exige_une_cible(appels):
    assert main.player_sync("p1", {"target": "p2"})["sync"] == "p2"
    assert appels[-1] == ("p1", ["sync", "p2"])
    with pytest.raises(HTTPException) as e:
        main.player_sync("p1", {"target": ""})
    assert e.value.status_code == 400
