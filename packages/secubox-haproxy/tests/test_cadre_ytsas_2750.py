# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2750 — ytsas encadre le lecteur PeerTube : son origine doit figurer dans frame-ancestors (liste explicite, jamais de joker)."""
import subprocess
from pathlib import Path

CTL = Path(__file__).resolve().parents[1] / "sbin" / "haproxyctl"


def ancetres(tmp_path, domaine):
    texte = CTL.read_text().splitlines()
    d = next(i for i, l in enumerate(texte) if l.startswith('_D="$(secubox-domaine'))
    f = next(i for i, l in enumerate(texte) if l.startswith("CADRE_ANCETRES="))
    bloc = "\n".join(texte[d:f + 1])
    faux = tmp_path / "bin"
    faux.mkdir(exist_ok=True)
    (faux / "secubox-domaine").write_text(f"#!/bin/sh\necho {domaine}\n")
    (faux / "secubox-domaine").chmod(0o755)
    r = subprocess.run(["bash", "-c", bloc + '\necho "$CADRE_ANCETRES"'], capture_output=True, text=True,
                       env={"PATH": f"{faux}:/usr/bin:/bin"})
    return r.stdout.strip().split()


def test_ytsas_de_la_box_peut_encadrer(tmp_path):
    a = ancetres(tmp_path, "gk2.secubox.in")
    assert "https://ytsas.gk2.secubox.in" in a and "https://billets.gk2.secubox.in" in a


def test_l_origine_suit_le_domaine_de_la_box(tmp_path):
    a = ancetres(tmp_path, "gk3.secubox.in")
    assert "https://ytsas.gk3.secubox.in" in a and "https://ytsas.gk2.secubox.in" not in a


def test_jamais_de_joker(tmp_path):
    assert not [x for x in ancetres(tmp_path, "gk2.secubox.in") if "*" in x]
