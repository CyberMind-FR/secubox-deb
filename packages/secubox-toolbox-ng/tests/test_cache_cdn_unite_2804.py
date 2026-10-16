# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2804 — cache des CDN statiques de sbxmitm : desactive par defaut, active PAR INSTANCE (deploiement par etapes), dossier prevu par le paquet."""
import re
from pathlib import Path

PAQUET = Path(__file__).resolve().parents[1]
UNITE = (PAQUET / "debian" / "secubox-toolbox-ng-worker@.service").read_text()
TMPFILES = (PAQUET / "tmpfiles" / "zz-secubox-cdn-cache.conf").read_text()
RULES = (PAQUET / "debian" / "rules").read_text()


def test_l_activation_se_fait_par_instance_et_n_est_pas_dans_l_unite():
    assert "EnvironmentFile=-/etc/secubox/toolbox-ng-worker-%i.env" in UNITE
    assert "$SBX_CDN_CACHE_ARGS" in UNITE.split("ExecStart=", 1)[1].split("Restart=", 1)[0]
    assert "--cdn-cache-dir" not in UNITE.replace("SBX_CDN_CACHE_ARGS=--cdn-cache-dir", ""), "le defaut est « desactive »"


def test_le_service_peut_ecrire_dans_le_cache_et_nulle_part_ailleurs():
    assert "ReadWritePaths=-/var/cache/secubox/cdn" in UNITE
    assert "ProtectSystem=strict" in UNITE and "NoNewPrivileges=yes" in UNITE


def test_le_dossier_appartient_au_compte_du_moteur():
    assert re.search(r"^d /var/cache/secubox/cdn\s+0755\s+secubox-toolbox\s+secubox", TMPFILES, re.M)


def test_le_tmpfiles_est_installe():
    assert "tmpfiles/zz-secubox-cdn-cache.conf" in RULES
