# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3217 — le registre des cookies de sbxwaf a de nouveau une rotation.

Sa règle vivait dans secubox-mitmproxy, purgé le 2026-09-08 (b51e0d330) : sur gk2, server.jsonl n'avait plus tourné
depuis le 19 août (219 Mo, 686 000 lignes) et secubox-metrics en tirait 1,4 Go de pic à chaque démarrage."""
import re
import shutil
import subprocess
from pathlib import Path

import pytest

REGLES = Path(__file__).resolve().parents[1] / "composants" / "waf" / "logrotate.d" / "secubox-waf"


def _bloc(chemin):
    texte = REGLES.read_text()
    debut = texte.index(chemin + " {")
    return texte[debut:texte.index("\n}", debut)]


def test_le_registre_des_cookies_tourne():
    b = _bloc("/var/log/secubox/cookie-audit/server.jsonl")
    for directive in ("su secubox-waf secubox-waf", "daily", "maxsize 20M", "compress", "missingok", "notifempty"):
        assert re.search(rf"^\s*{directive}\s*$", b, re.M), directive
    # sbxwaf garde le fichier ouvert (O_APPEND, ouvert une fois, jamais rouvert) : un renommage le laisserait écrire
    # dans le fichier tourné. copytruncate est donc requis ici — et seulement ici (le journal d'audit CSPN, lui, ne
    # se tronque jamais).
    assert re.search(r"^\s*copytruncate\s*$", b, re.M)
    assert not re.search(r"^\s*create\b", b, re.M)


def test_le_journal_des_menaces_reste_sans_troncature():
    assert not re.search(r"^\s*copytruncate\s*$", _bloc("/var/log/secubox/waf/waf-threats.log"), re.M)


def _compte(nom):
    import pwd
    try:
        pwd.getpwnam(nom)
        return True
    except KeyError:
        return False


@pytest.mark.skipif(not shutil.which("logrotate") or not _compte("secubox-waf"),
                    reason="logrotate ou le compte secubox-waf absent (la directive su ne se vérifie que sur une box)")
def test_logrotate_accepte_les_regles(tmp_path):
    etat = tmp_path / "etat"
    r = subprocess.run(["logrotate", "-d", "-s", str(etat), str(REGLES)], capture_output=True, text=True)
    erreurs = [ligne for ligne in (r.stdout + r.stderr).splitlines() if re.search(r"\berror\b", ligne, re.I)
               and "No such file" not in ligne]
    assert not erreurs, erreurs
