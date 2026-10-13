# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2532 — secubox-dpi-resume : 226/NAMESPACE quand /var/cache/secubox/dpi n'existe pas.

`ProtectSystem=strict` + `ReadWritePaths=<dossier absent>` : systemd ne peut pas monter le chemin et n'exécute rien. CacheDirectory= crée le
dossier AVANT l'espace de noms (et le rend inscriptible)."""
import re
from pathlib import Path

UNITE = (Path(__file__).resolve().parents[1] / "systemd" / "secubox-dpi-resume.service").read_text()


def test_le_dossier_de_cache_est_cree_par_systemd():
    assert re.search(r"^CacheDirectory=secubox/dpi$", UNITE, re.M)


def test_pas_de_chemin_inscriptible_sans_garantie_d_existence():
    for chemin in re.findall(r"^ReadWritePaths=(.+)$", UNITE, re.M):
        for c in chemin.split():
            assert c.startswith("-") or c.rstrip("/") == "/var/cache/secubox/dpi" and "CacheDirectory=secubox/dpi" in UNITE, c
