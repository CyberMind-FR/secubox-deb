# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2863 — la bibliothèque de listes de filtres vit dans `secubox_filterlists` (secubox-core), pas dans secubox-toolbox.

secubox-adblock-sync (ad-guard) et /sinkhole/sources (dns-guard) l'importaient depuis secubox_toolbox : sur le profil `minimal` (sans toolbox), la mise à jour du puits DNS
publicitaire échouait (« cannot import name 'filterlists' from 'secubox_toolbox' »)."""
import importlib
import re
import sys
from pathlib import Path

RACINE = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(RACINE / "common"))
sys.path.insert(0, str(RACINE / "packages" / "secubox-toolbox"))


def test_la_bibliotheque_est_importable_sans_le_toolbox():
    F = importlib.import_module("secubox_filterlists")
    for nom in ("load_sources", "compile_lists", "OUT_DNS", "DATA_DIR", "SOURCES_FILE"):
        assert hasattr(F, nom), nom


def test_la_bibliotheque_est_stdlib_pure():
    """Livrée par secubox-core : aucune dépendance au toolbox ni à FastAPI."""
    src = (RACINE / "common" / "secubox_filterlists" / "__init__.py").read_text(encoding="utf-8")
    assert "secubox_toolbox" not in src.replace("secubox_toolbox.filterlists", "").replace("`secubox_toolbox`", "")
    assert "fastapi" not in src.lower()


def test_l_ancien_chemin_du_toolbox_reste_valable():
    """Compatibilité : `from secubox_toolbox import filterlists` rend la MÊME bibliothèque."""
    ancien = importlib.import_module("secubox_toolbox.filterlists")
    nouveau = importlib.import_module("secubox_filterlists")
    assert ancien is nouveau


def test_le_paquet_core_livre_la_bibliotheque():
    rules = (RACINE / "packages" / "secubox-core" / "debian" / "rules").read_text(encoding="utf-8")
    assert "common/secubox_filterlists" in rules


def test_ad_guard_et_dns_guard_l_importent_de_la():
    sync = (RACINE / "packages" / "secubox-ad-guard" / "sbin" / "secubox-adblock-sync").read_text(encoding="utf-8")
    dns = (RACINE / "packages" / "secubox-dns-guard" / "api" / "main.py").read_text(encoding="utf-8")
    assert "import secubox_filterlists" in sync or "from secubox_filterlists" in sync
    assert "secubox_filterlists" in dns
    ctl = (RACINE / "packages" / "secubox-ad-guard" / "debian" / "control").read_text(encoding="utf-8")
    plancher = re.search(r"secubox-core \(>= ([0-9.]+)\)", ctl)                 # 1.7.10 livre secubox_filterlists ; un plancher plus haut convient
    assert plancher and tuple(map(int, plancher.group(1).split("."))) >= (1, 7, 10)
