# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2050 (D3) : vortex-dns est RETIRÉ (décision du propriétaire, 2026-10-08).

Constat : actif sur gk2 mais jamais branché (aucun RPZ côté Unbound, dossiers de listes et de zones vides) ; un seul moteur DNS vit, Unbound,
piloté par ad-guard et webfilter. Le paquet devient transitoire et vide (il disparaît de la machine à la mise à jour) ; il sera supprimé
du dépôt un cycle après sa publication."""
import re
from pathlib import Path

RACINE = Path(__file__).resolve().parents[2]
PAQ = RACINE / "packages" / "secubox-vortex-dns"


def test_le_paquet_est_retire_du_depot():
    assert not PAQ.exists(), "secubox-vortex-dns : transitoire retiré (publié dans alpha.10)"


def test_plus_dans_le_catalogue_ni_dans_l_arbre_des_meta_paquets():
    assert "secubox-vortex-dns" not in (RACINE / "packages" / "secubox-appstore" / "groupes.yaml").read_text()
    arbre = (RACINE / "packages" / "secubox-meta" / "arbre.yaml").read_text()
    avant, _, hors = arbre.partition("\nhors-arbre:")
    assert not re.search(r"^\s*-\s*secubox-vortex-dns\b", avant, re.M), "plus dans l'arbre des fonctions"
    assert re.search(r"^\s*-\s*secubox-vortex-dns\b", hors, re.M), "déclaré hors-arbre (retiré) : sinon le générateur échoue"


def test_le_hub_ne_route_plus_vortex_dns():
    nginx = (RACINE / "packages" / "secubox-hub" / "nginx" / "webui.conf").read_text()
    assert "vortex-dns" not in nginx
    assert "/vortex-dns/" not in (RACINE / "packages" / "secubox-hub" / "www" / "shared" / "unknown-module.html").read_text()
