# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2240 : le capteur DPI est livré armé par la configuration, et le groupe d'ingestion est donné par le postinst — pas par l'unité."""
from pathlib import Path

PKG = Path(__file__).resolve().parents[2] / "packages" / "secubox-toolbox-ng"


def sans_commentaires(t):
    return "\n".join(l for l in t.splitlines() if not l.lstrip().startswith("#"))


def test_dpi_env_arme_le_capteur_sur_le_socket_d_actord():
    env = sans_commentaires((PKG / "debian" / "dpi.env").read_text())
    assert "DPI_ACTOR_SOCK=/run/secubox/actord.sock" in env


def test_le_postinst_ajoute_le_groupe_et_l_unite_n_en_depend_pas():
    post = (PKG / "debian" / "postinst").read_text()
    assert "usermod -aG actord-ingest secubox-toolbox" in post and "getent group actord-ingest" in post
    assert post.index("usermod -aG actord-ingest") < post.index("#DEBHELPER#")           # avant le redémarrage de sbxdpi
    unite = sans_commentaires((PKG / "debian" / "sbxdpi.service").read_text())
    assert "SupplementaryGroups" not in unite and "NoNewPrivileges=yes" in unite and "User=secubox-toolbox" in unite
