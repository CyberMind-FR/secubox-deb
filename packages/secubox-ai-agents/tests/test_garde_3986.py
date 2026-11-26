# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Tranche A (#3986) : garde et unité. Sans OpenJarvis : tournent aussi en CI."""
import subprocess
from pathlib import Path

import pytest

from conftest import PAQUET

UNITE = PAQUET / "systemd/secubox-ai-agents-gk0.service"


def test_jeton_lisible_par_d_autres_refuse(tmp_path):
    from agents import garde
    j = tmp_path / "j"
    j.write_text("x" * 40)
    j.chmod(0o644)
    with pytest.raises(RuntimeError, match="0600"):
        garde.lire_jeton(j)
    j.chmod(0o600)
    assert garde.lire_jeton(j) == "x" * 40


def test_mode_inconnu_refuse(monkeypatch):
    from agents import garde
    monkeypatch.setenv("SECUBOX_AI_AGENTS_GARDE", "ouvert")
    with pytest.raises(RuntimeError, match="inconnu"):
        garde.construire()


def test_mode_secubox_est_require_jwt_de_secubox_core():
    """Mode par défaut d'une box : la VRAIE garde de secubox_core (interpréteur du dépôt, common/ au chemin)."""
    py = Path(PAQUET.parents[1], ".venv/bin/python")
    if not py.exists():
        py = Path("/home/reepost/CyberMindStudio/secubox-deb/secubox-deb/.venv/bin/python")
    if not py.exists():
        pytest.skip("interpréteur du dépôt SecuBox absent")
    code = ("import os, sys; os.environ.pop('SECUBOX_AI_AGENTS_GARDE', None); sys.path[:0] = [sys.argv[1], sys.argv[2]];"
            "from agents import garde; from secubox_core.auth import require_jwt;"
            "assert garde.mode() == 'secubox' and garde.construire() is require_jwt; print('ok')")
    r = subprocess.run([str(py), "-c", code, str(PAQUET), str(PAQUET.parents[1] / "common")],
                       capture_output=True, text=True, timeout=60)
    assert r.returncode == 0 and r.stdout.strip() == "ok", r.stderr


def test_unite_durcie_sans_reseau():
    t = UNITE.read_text()
    for ligne in ("RestrictAddressFamilies=AF_UNIX", "NoNewPrivileges=yes", "ProtectSystem=strict",
                  "PrivateUsers=yes", "CapabilityBoundingSet=", "UMask=0077",
                  "Environment=SECUBOX_AI_AGENTS_GARDE=jeton-local", "Environment=OPENJARVIS_NO_UPDATE_CHECK=1"):
        assert ligne in t.splitlines(), ligne
    assert "User=root" not in t and "--host" not in t
