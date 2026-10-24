# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3093 — sur MOCHAbin, le switch DSA se charge dans l'initrd, avant toute ouverture d'eth2.

Banc 2026-10-24 (noyau Debian stock) : mv88e6xxx chargé par udev après l'ouverture d'eth2 → mvpp2 bascule ses
tampons, rouvre tous les ports, le PHY d'eth2 est rattaché une 2e fois et ne remonte jamais (#2004)."""
from pathlib import Path

TEXTE = (Path(__file__).resolve().parents[1] / "image" / "build-image.sh").read_text()
BLOC = TEXTE[TEXTE.index("# Hook 2:"):TEXTE.index("# Also create the modprobe.d config in rootfs")]


def test_mochabin_charge_le_switch_dans_l_initrd():
    i_moch = BLOC.index('if [[ "${BOARD}" == "mochabin" ]]; then')
    i_mods = BLOC.index("/etc/initramfs-tools/modules")
    i_else = BLOC.index("else", i_moch)
    assert i_moch < i_mods < i_else
    assert "dsa_core" in BLOC[i_moch:i_else] and "mv88e6xxx" in BLOC[i_moch:i_else]
    # Banc 2026-10-24 : sans tag_dsa (étiquettes DSA/EDSA Marvell), la sonde de l'initrd est remise à après la
    # racine (2e « switch detected » à 12,9 s) ; avec, switch prêt à 5,1 s, « DSA: tree 0 setup » avant la racine.
    assert "tag_dsa" in BLOC[i_moch:i_else]


def test_les_autres_cartes_gardent_la_liste_noire_de_l_initrd():
    # ESPRESSObin : prudence de #2146 conservée
    i_else = BLOC.index("else", BLOC.index('if [[ "${BOARD}" == "mochabin" ]]; then'))
    assert "mv88e6xxx-blacklist" in BLOC[i_else:]
    assert "blacklist mv88e6xxx" in BLOC[i_else:]
