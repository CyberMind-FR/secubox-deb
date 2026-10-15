# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2177 : l'image ESPRESSObin ne charge plus le pilote wifi ath10k et n'active plus les pages géantes transparentes.

MESURÉ le 2026-10-15 sur une ESPRESSObin v7 (1 Go, U-Boot 2021.01, démarrage USB) : quatre démarrages consécutifs gelaient les deux cœurs
à 48,02 s (« hard LOCKUP », puis « soft lockup … [khugepaged] »). Écartés par essai : le pilote DSA (mv88e6xxx bloqué dans les trois
premiers), AppArmor (`apparmor=0 security=none`). Le seul changement qui a levé le gel : `modprobe.blacklist=…,ath10k_pci,ath10k_core`.
La carte porte une Qualcomm 168c:003c en mPCIe, dont le noyau signale `BAR 0: error updating`. Aucune carte wifi n'est utilisée par le
profil lite (pas de hostapd).

`transparent_hugepage=never` : `khugepaged` est le fil que le noyau signale figé ; sur 1 Go, défragmenter pour des pages de 2 Mio n'apporte
rien et ajoute de la pression mémoire."""
import re
from pathlib import Path

RACINE = Path(__file__).resolve().parents[2]
CARTE = RACINE / "board" / "espressobin-v7"

# Fichiers qui écrivent la ligne de commande du noyau pour l'Armada 3720. Chacun est lu, le test n'en suppose aucun.
FICHIERS = [
    CARTE / "boot.cmd",
    CARTE / "boot-usb.cmd",
    CARTE / "boot-live-usb.cmd",
    CARTE / "extlinux" / "extlinux.conf",
    RACINE / "image" / "build-image.sh",
]


def lignes_noyau(chemin):
    """Les lignes qui portent le blocage DSA : c'est là que vit la ligne de commande."""
    return [ligne for ligne in chemin.read_text(encoding="utf-8").splitlines() if "modprobe.blacklist=mv88e6xxx" in ligne]


def test_chaque_fichier_a_au_moins_une_ligne_de_commande():
    for f in FICHIERS:
        assert lignes_noyau(f), f"{f.relative_to(RACINE)} : aucune ligne modprobe.blacklist=mv88e6xxx trouvée, le test ne vérifie plus rien"


def test_ath10k_est_bloque_partout():
    for f in FICHIERS:
        for ligne in lignes_noyau(f):
            m = re.search(r"modprobe\.blacklist=(\S+)", ligne)
            noms = set(m.group(1).split(","))
            assert {"ath10k_pci", "ath10k_core"} <= noms, f"{f.relative_to(RACINE)} : ath10k non bloqué ({sorted(noms)})"


def test_le_blocage_du_pilote_dsa_est_conserve():
    for f in FICHIERS:
        for ligne in lignes_noyau(f):
            m = re.search(r"modprobe\.blacklist=(\S+)", ligne)
            assert {"mv88e6xxx", "dsa_core"} <= set(m.group(1).split(",")), f.name


def test_pages_geantes_transparentes_desactivees_partout():
    for f in FICHIERS:
        for ligne in lignes_noyau(f):
            assert "transparent_hugepage=never" in ligne, f"{f.relative_to(RACINE)} : transparent_hugepage=never absent"


def test_un_seul_parametre_modprobe_blacklist_par_ligne():
    """Deux `modprobe.blacklist=` sur une ligne : kmod les lit tous, mais un test ne doit pas dépendre de ce détail de lecture."""
    for f in FICHIERS:
        for ligne in lignes_noyau(f):
            assert ligne.count("modprobe.blacklist=") == 1, f"{f.relative_to(RACINE)} : paramètre répété"
