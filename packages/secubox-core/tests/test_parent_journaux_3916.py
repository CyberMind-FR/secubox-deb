# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3916 : le parent partagé /var/log/secubox reste root:root.

`LogsDirectory=secubox` sur une unité `User=secubox` fait re-chowner par systemd TOUT
/var/log/secubox (journaux du WAF compris) dès que le parent appartient à un autre
compte ; un postinst qui réattribue le parent ré-arme ce va-et-vient à chaque installation.
"""
import re
from pathlib import Path

RACINE = Path(__file__).resolve().parents[3] / "packages"
CONSTRUIT = re.compile(r"/debian/secubox-[^/]+/")      # arbres de build dh, hors source


def _sources(motif):
    return [p for p in RACINE.glob(motif) if not CONSTRUIT.search(str(p))]


def test_aucune_unite_ne_declare_le_parent_en_logsdirectory():
    fautives = [str(p.relative_to(RACINE)) for p in _sources("**/*.service")
                if re.search(r"^LogsDirectory=(.*\s)?secubox(\s|$)", p.read_text(errors="replace"), re.M)]
    assert fautives == []


def test_aucun_postinst_ne_reattribue_le_parent():
    reattrib = re.compile(r"(install -d[^\n]*-o\s+(?!root\b)\S+[^\n]*|chown\s+\S+)\s+/var/log/secubox/?\s*$", re.M)
    fautifs = [str(p.relative_to(RACINE)) for p in _sources("**/postinst") if reattrib.search(p.read_text(errors="replace"))]
    assert fautifs == []
