# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""La base d'ingestion mitm est dans un répertoire que l'API (secubox) peut écrire, pas dans celui de root."""
import re
from pathlib import Path

PKG = Path(__file__).resolve().parents[1]


def test_la_base_n_est_pas_dans_le_repertoire_de_root():
    main = (PKG / "api" / "main.py").read_text()
    chemin = re.search(r'db_path="([^"]+mitm-ingest\.db)"', main).group(1)
    assert chemin.startswith("/var/lib/secubox/dpi-ingest/"), chemin
    postinst = (PKG / "debian" / "postinst").read_text()
    # le répertoire de root reste root (le collecteur y écrit) ; celui de la base appartient à secubox
    assert "install -d -o root -g root -m 0755 /var/lib/secubox/dpi\n" in postinst
    assert "install -d -o secubox -g secubox -m 0755 /var/lib/secubox/dpi-ingest" in postinst
