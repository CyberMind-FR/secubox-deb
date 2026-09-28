# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""La curation livrée est celle que le Hall déclare (FEATURED) — test de dérive (#1605)."""
import importlib.util
import json
from pathlib import Path

ICI = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("extraire", ICI / "outils" / "extraire-curation.py")
extraire = importlib.util.module_from_spec(spec)
spec.loader.exec_module(extraire)


def test_curation_livree_egale_au_hall():
    hall = ICI.parent / "secubox-webos" / "www" / "hall" / "index.html"
    attendu = extraire.extrait(hall.read_text(encoding="utf-8"))
    livre = json.loads((ICI / "www" / "mine" / "curation.json").read_text(encoding="utf-8"))["lieux"]
    assert livre == attendu, "curation.json a dérivé : relancer outils/extraire-curation.py"


def test_aide_n_ecrit_rien(tmp_path, capsys):
    cible = tmp_path / "c.json"
    try:
        extraire.main(["--help"])
    except SystemExit:
        pass
    assert not cible.exists()
