# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""SecuBox-Deb :: nac — les interfaces scannées sont extensibles (#1035)

CyberMind — https://cybermind.fr

POURQUOI CE TEST EXISTE. La liste des interfaces était écrite en dur et
n'incluait pas `eth2` — par lequel gk2 voit justement tout son LAN. La
découverte ARP filtrait donc chaque voisin, et le tableau de bord affichait
ZÉRO client.

CE DÉFAUT NE SE SIGNALE PAS : « aucun client » est un état parfaitement
légitime pour un module de contrôle d'accès. Rien n'échoue, rien ne se
journalise — on conclut que le réseau est calme. Le correctif existait sur la
board depuis longtemps et n'avait jamais été remonté dans le code : installer
la version du dépôt aurait vidé l'inventaire.
"""
from __future__ import annotations

import sys
from pathlib import Path

# `main.py` fait des imports RELATIFS : il doit etre charge comme membre du
# paquet `api`, jamais isolement — c'est aussi ainsi que l'agregateur le monte.
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from api import main as m


def test_les_defauts_couvrent_les_ponts_usuels():
    assert {"br-lan", "br-lxc", "eth0"} <= m._DEFAULT_LAN_INTERFACES


def test_la_config_ETEND_les_defauts(monkeypatch):
    """ON ÉTEND, ON NE REMPLACE PAS : une config qui se substituerait ferait
    disparaître les ponts au premier oubli."""
    monkeypatch.setattr(m, "get_config", lambda _: {"lan_interfaces": ["eth2"]})
    ifs = m._lan_interfaces()
    assert "eth2" in ifs
    assert m._DEFAULT_LAN_INTERFACES <= ifs


def test_une_chaine_separee_par_virgules_est_acceptee(monkeypatch):
    """La config est écrite à la main : les deux écritures doivent passer."""
    monkeypatch.setattr(m, "get_config",
                        lambda _: {"lan_interfaces": "eth2, eth3 ,"})
    ifs = m._lan_interfaces()
    assert {"eth2", "eth3"} <= ifs
    assert "" not in ifs


def test_une_config_illisible_rend_les_defauts_pas_le_vide(monkeypatch):
    """UN INVENTAIRE PARTIEL VAUT MIEUX QU'UN INVENTAIRE VIDE : rendre un
    ensemble vide ferait disparaître tous les clients, ce qui est exactement le
    défaut qu'on corrige."""
    def explose(_):
        raise OSError("config illisible")
    monkeypatch.setattr(m, "get_config", explose)
    assert m._lan_interfaces() == m._DEFAULT_LAN_INTERFACES


def test_sans_config_les_defauts_suffisent(monkeypatch):
    monkeypatch.setattr(m, "get_config", lambda _: {})
    assert m._lan_interfaces() == m._DEFAULT_LAN_INTERFACES
