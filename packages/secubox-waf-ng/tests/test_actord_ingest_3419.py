# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3419 — secubox-actord-ingest n'est plus tué en plein travail par un redémarrage d'actord (Result=signal)."""
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
UNIT = (ROOT / "systemd" / "secubox-actord-ingest.service").read_text()
ACTORD = (ROOT / "systemd" / "secubox-actord.service").read_text()
SCRIPT = (ROOT / "sbin" / "secubox-actord-ingest-perms").read_text()


def test_ni_bindsto_ni_partof_mais_relance_par_actord():
    assert not re.search(r"^(BindsTo|PartOf)=", UNIT, re.M)
    assert re.search(r"^After=secubox-actord\.service$", UNIT, re.M)
    assert re.search(r"^Wants=secubox-actord-ingest\.service$", ACTORD, re.M)
    assert not re.search(r"^RemainAfterExit=", UNIT, re.M)


def test_attente_bornee_couverte_par_le_delai():
    attente = int(re.search(r"^ATTENTE=(\d+)", SCRIPT, re.M).group(1))
    delai = int(re.search(r"^TimeoutStartSec=(\d+)$", UNIT, re.M).group(1))
    assert delai > attente + 10
    assert SCRIPT.rstrip().endswith("exit 0")


# ── #3939 : sans actord, l'unité est passée au lieu d'attendre 960 s et d'échouer (un changement de profil annulé) ──
def test_ingest_passee_sans_actord_actif():
    assert re.findall(r"^ExecCondition=(.*)$", UNIT, re.M) == ["/bin/systemctl -q is-active secubox-actord.service"]
    # une CONDITION, pas un ExecStartPre (dont l'échec met l'unité en échec), et avant l'attente de la socket
    assert "ExecStartPre=" not in UNIT and UNIT.index("ExecCondition=") < UNIT.index("\nExecStart=")


def test_actord_est_actif_pendant_tout_son_rejeu():
    """La condition ne vaut que si « active » ne veut pas dire « socket ouverte » : Type=simple, sans ExecStartPre ni ExecStartPost
    (« activating » tant qu'ils tournent). Un passage à Type=notify/exec long ferait passer l'unité pendant les 11 min de rejeu."""
    assert re.findall(r"^Type=(.*)$", ACTORD, re.M) == ["simple"]
    assert not re.search(r"^ExecStart(Pre|Post)=", ACTORD, re.M)


def test_ingest_toujours_tiree_par_le_demarrage_d_actord():
    assert re.search(r"^WantedBy=secubox-actord\.service$", UNIT, re.M)
    assert re.search(r"^Wants=secubox-actord-ingest\.service$", ACTORD, re.M)
    assert re.search(r"^After=secubox-actord\.service$", UNIT, re.M)     # la condition est lue une fois actord actif
    assert not re.search(r"^(Requires|Requisite)=", UNIT, re.M)
