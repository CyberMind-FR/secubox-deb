# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""#3869 : un échec imprévu de `apply` rend un refus lisible et audité, jamais une trace brute ; l'API garde la fin du
message (là où Python écrit la cause), pas son début."""
import json
import subprocess
from pathlib import Path

import pytest
from fastapi import HTTPException

from api import dnstv, dnstv_routes
from test_dnstv_ctl_api import ctl, declarer, monde  # noqa: F401


def test_apply_imprevu_audite_sans_trace(monde, monkeypatch, capsys):  # noqa: F811
    declarer(monde, "block")
    bloc = monde["tmp"] / "pas-un-dossier"
    bloc.write_text("x")
    conf = bloc / "94-secubox-adguard-tv.conf"                       # parent = un fichier : OSError imprévue à l'écriture
    monkeypatch.setenv("SECUBOX_ADGUARD_TV_UNBOUND", str(conf))
    monkeypatch.setattr(dnstv, "CONF_UNBOUND", conf)
    assert ctl(monde, "apply") == 1
    sortie = capsys.readouterr()
    assert "Traceback" not in sortie.err + sortie.out
    assert json.loads(sortie.out) == {"ok": False, "action": "apply", "erreur": "NotADirectoryError"}
    assert "NotADirectoryError" in sortie.err and len(sortie.err) < 300
    assert "apply-echec" in (monde["tmp"] / "audit.log").read_text()


def test_api_garde_la_fin_du_message(monkeypatch):
    long = "Traceback (most recent call last):\n" + "  ligne\n" * 80 + "OSError: la vraie cause"
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: subprocess.CompletedProcess(a, 1, "", long))
    with pytest.raises(HTTPException) as e:
        dnstv_routes._ctl("apply")
    assert e.value.detail.endswith("OSError: la vraie cause") and len(e.value.detail) <= 300
