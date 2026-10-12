# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""#2490 — le postinst de la Toolbox ne reprend pas le dossier partagé /var/log/secubox à la rotation générale de secubox-core."""
import re
from pathlib import Path

POSTINST = (Path(__file__).resolve().parents[1] / "debian" / "postinst").read_text(encoding="utf-8")


def _ligne():
    m = re.findall(r"^\s*install -d (-m \d+) (-o \S+) (-g \S+) /var/log/secubox\s*$", POSTINST, re.M)
    assert len(m) == 1, m
    return m[0]


def test_le_dossier_partage_est_ouvert_au_groupe_de_la_rotation():
    mode, proprio, groupe = _ligne()
    assert groupe == "-g secubox"                                   # la rotation tourne sous `su secubox secubox`
    assert int(mode.split()[1], 8) & 0o020 and int(mode.split()[1], 8) & 0o005 == 0o005     # groupe peut écrire ; reste traversable et lisible par tous


def test_le_service_garde_la_main_sur_ses_journaux():
    assert _ligne()[1] == "-o secubox-toolbox"


def test_le_dossier_n_est_jamais_plus_ferme_que_0755():
    """Régression #511 : un 0750 casse les tableaux de bord WAF et SOC lus par le compte `secubox`."""
    assert int(_ligne()[0].split()[1], 8) >= 0o755
