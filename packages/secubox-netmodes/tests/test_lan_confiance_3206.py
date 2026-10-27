# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3206 — le LAN du mode routeur est de confiance « comme le réseau de la Freebox » (décision du 2026-10-26) : en entrée,
même accès que `iif "eth2" accept` du durcissement. Constaté sur gk4 (2026-10-27) : un nœud du LAN routé ne joignait pas
l'API de jonction du maillage (7331), ni SSH, ni rien d'autre que DHCP et DNS. SSH est inséré en tête : le durcissement
refuse le 22 hors de 10/8 et 192.168.1.0/24 plus haut dans la chaîne. Jamais les ports isolés (lanN, #3201)."""
from test_routeur_rendu_3189 import lignes, sortie  # noqa: F401  (fixture)

CONFIANCE = 'add rule inet filter input iifname "br-lan" accept comment "secubox netmodes lan confiance"'
SSH = 'insert rule inet filter input iifname "br-lan" tcp dport 22 accept comment "secubox netmodes lan ssh"'


def test_lan_de_confiance_en_entree(sortie):  # noqa: F811
    rendu = lignes(sortie["nft"])
    assert CONFIANCE in rendu
    assert SSH in rendu


def test_regles_d_entree_retirees_par_le_retour(sortie):  # noqa: F811
    """Le retour et la réapplication suppriment par le préfixe du commentaire : les deux règles le portent."""
    for ligne in (CONFIANCE, SSH):
        assert 'comment "secubox netmodes lan ' in ligne


def test_seul_br_lan_jamais_un_port_ni_le_wan(sortie):  # noqa: F811
    for ligne in lignes(sortie["nft"]):
        if " inet filter input " in ligne:
            assert 'iifname "br-lan"' in ligne, ligne
            assert "lan0" not in ligne and "lan1" not in ligne and "eth" not in ligne, ligne
