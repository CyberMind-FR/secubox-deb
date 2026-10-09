# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""L'image ESPRESSObin ne charge plus le pilote DSA au démarrage, par prudence (#2146).

ATTENTION, ce test ne dit PAS que le pilote cause le gel observé au premier démarrage réel (ESPRESSObin v7, U-Boot 2021.01, USB) : un
deuxième essai avec `systemd.mask=mv88e6xxx-load.service` fige les deux cœurs de la même façon (« hard LOCKUP on cpu 0 », « soft lockup -
CPU#1 stuck for 52s! [khugepaged] », juste après auditd). Le pilote reste donc hors du chemin critique du premier essai, `eth0` prend
l'adresse en DHCP, et la cause du gel se cherche ailleurs. Opt-in : DSA_LOAD=1."""
import re
from pathlib import Path

RACINE = Path(__file__).resolve().parents[2]
SCRIPT = (RACINE / "image" / "build-image.sh").read_text(encoding="utf-8")
NETPLAN = (RACINE / "board" / "espressobin-v7" / "netplan" / "00-secubox.yaml").read_text(encoding="utf-8")


def test_le_chargement_du_pilote_dsa_est_opt_in():
    assert 'DSA_LOAD="${DSA_LOAD:-0}"' in SCRIPT
    bloc = SCRIPT.split("mv88e6xxx-load.service")[-2:]
    assert re.search(r'if \[\[ "\$\{DSA_LOAD\}" == "1" \]\]; then\s+chroot "\$\{ROOTFS\}" systemctl enable mv88e6xxx-load\.service', SCRIPT), \
        "le service ne doit être activé que si DSA_LOAD=1"
    assert "systemctl disable mv88e6xxx-load.service" in SCRIPT


def test_eth0_prend_l_adresse_quand_le_commutateur_n_est_pas_gere():
    m = re.search(r"^    eth0:\n((?:      .*\n)+)", NETPLAN, re.M)
    assert m and re.search(r"dhcp4:\s*true", m.group(1))
