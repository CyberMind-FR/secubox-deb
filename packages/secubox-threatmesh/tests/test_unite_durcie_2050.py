# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""#2050 vague 0 : l'unité threatmesh (root, écoute 0.0.0.0:8780) est confinée au mieux sans changer d'utilisateur."""
import re
from pathlib import Path

UNITE = (Path(__file__).resolve().parents[1] / "systemd/secubox-threatmesh.service").read_text()


def test_no_new_privileges():
    assert re.search(r"(?m)^NoNewPrivileges=yes\s*$", UNITE)


def test_durcissements_de_base():
    for d in ("ProtectSystem=full", "ProtectHome=true", "RestrictSUIDSGID=true", "PrivateTmp=true"):
        assert re.search(rf"(?m)^{d}\s*$", UNITE), d


def test_pare_feu_du_port_maillage_charge_avant_le_demarrage():
    assert "ExecStartPre=-/usr/sbin/nft -f /usr/share/secubox/threatmesh/nftables.d/secubox-threatmesh.nft" in UNITE
