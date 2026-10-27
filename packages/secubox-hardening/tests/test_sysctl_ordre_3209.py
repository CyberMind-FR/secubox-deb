# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""#3209 — appliquer le durcissement ne coupe plus le routage.

99-secubox-hardening.conf porte `net.ipv4.ip_forward = 0` ; au démarrage, 99-secubox-zz-lxc-forward.conf
(secubox-core) passe après et remet 1. `sysctl -p` sur le seul fichier de hardening ne le rejouait pas : la mise à jour
1.6.2 a laissé gk1, gk3 et gk4 sans routage (LXC et LAN routé) jusqu'à un `sysctl --system` (2026-10-27)."""
import re
from pathlib import Path

PAQUET = Path(__file__).resolve().parents[1]
APPLIQUENT = [PAQUET / "debian" / "postinst", PAQUET / "sbin" / "hardeningctl"]


def _code(chemin):
    """Les lignes exécutées, sans les commentaires."""
    return [ligne for ligne in chemin.read_text().splitlines() if not ligne.lstrip().startswith("#")]


def test_jamais_sysctl_p_sur_le_seul_fichier_de_hardening():
    for chemin in APPLIQUENT:
        fautives = [ligne for ligne in _code(chemin) if re.search(r"\bsysctl\b.*\s-p\b", ligne)]
        assert not fautives, f"{chemin.name} : {fautives}"


def test_ordre_du_demarrage_par_sysctl_system():
    for chemin in APPLIQUENT:
        assert any(re.search(r"\bsysctl\b.*--system\b", ligne) for ligne in _code(chemin)), chemin.name


def test_le_fichier_livre_garde_son_ip_forward_a_zero():
    """Le fichier n'est pas changé par #3209 : seul l'ordre d'application compte."""
    conf = (PAQUET / "conf" / "99-secubox-hardening.conf").read_text()
    assert re.search(r"^net\.ipv4\.ip_forward\s*=\s*0", conf, re.M)
