# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""Conteneur LXC en dernière Debian stable (#3285) : la suite par défaut est
celle de l'hôte (`suite_debian_hote`, repli trixie), jamais `bookworm` en dur."""
import ast
import os
import re
from pathlib import Path

MAIN = Path(__file__).resolve().parents[1] / "api" / "main.py"


def _fonction():
    """suite_debian_hote() isolée par l'AST, sans importer l'API (FastAPI, secubox_core)."""
    arbre = ast.parse(MAIN.read_text(encoding="utf-8"))
    noeuds = [n for n in arbre.body
              if (isinstance(n, ast.FunctionDef) and n.name == "suite_debian_hote")
              or (isinstance(n, ast.Assign) and any(getattr(c, "id", "") == "SUITE_DEBIAN_REPLI" for c in n.targets))]
    espace = {"os": os, "re": re}
    exec(compile(ast.Module(body=noeuds, type_ignores=[]), str(MAIN), "exec"), espace)
    return espace["suite_debian_hote"]


def test_aucune_suite_bookworm_par_defaut():
    texte = MAIN.read_text(encoding="utf-8")
    assert '"-r", "bookworm"' not in texte and "debian/ bookworm" not in texte
    assert '"-r", suite_debian_hote()' in texte
    # Dépôt packages.matrix.org : suite lue DANS le conteneur ; pièges de trixie.
    assert 'debian/ $(. /etc/os-release && echo "$VERSION_CODENAME") main' in texte
    assert "ImportCredential=" in texte and "wget gpg apt-transport-https" in texte


def test_suite_lue_dans_os_release(tmp_path, monkeypatch):
    monkeypatch.delenv("SECUBOX_DEBIAN_SUITE", raising=False)
    suite = _fonction()
    osr = tmp_path / "os-release"
    osr.write_text('PRETTY_NAME="Debian GNU/Linux 14 (forky)"\nID=debian\nVERSION_CODENAME=forky\n')
    assert suite(str(osr)) == "forky"
    osr.write_text("ID=ubuntu\nVERSION_CODENAME=noble\n")
    assert suite(str(osr)) == "trixie"
    assert suite(str(tmp_path / "absent")) == "trixie"
    monkeypatch.setenv("SECUBOX_DEBIAN_SUITE", "bookworm")
    assert suite(str(osr)) == "bookworm"
    monkeypatch.setenv("SECUBOX_DEBIAN_SUITE", "x; rm -rf /")
    assert suite(str(osr)) == "trixie"
