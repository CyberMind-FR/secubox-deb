# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2050 (vague 0) — netmodes n'utilise plus iptables : le projet impose nftables.

`apply_mtu_clamping` appelait `iptables -A FORWARD …` : interdit par les règles du projet, et chaque appel AJOUTAIT une
règle de plus (rien ne la retirait). Le serrage du MSS est maintenant une table nftables dédiée, recréée à chaque appel."""
import subprocess
from pathlib import Path
from unittest import mock

from fastapi.testclient import TestClient

import secubox_core.config as _cfg

_cfg._CONFIG = {"global": {}, "api": {"socket_dir": "/tmp/secubox", "jwt_secret": "test"}, "auth": {"users": {}}}
with mock.patch("pathlib.Path.mkdir"):
    from api import main  # noqa: E402

SOURCE = Path(main.__file__).read_text()


def test_le_module_n_appelle_plus_iptables():
    # un appel = le nom entre guillemets dans une liste d'arguments (le commentaire qui explique le changement est permis)
    assert '"iptables"' not in SOURCE and "'iptables'" not in SOURCE
    assert "ip6tables" not in SOURCE


def test_le_serrage_du_mss_passe_par_nft_et_est_idempotent(monkeypatch):
    appels = []

    def faux_run(cmd, **kw):
        appels.append((list(cmd), kw.get("input")))
        return subprocess.CompletedProcess(cmd, 0, "", "")

    monkeypatch.setattr(main.subprocess, "run", faux_run)
    main.app.dependency_overrides[main.require_jwt] = lambda: {"sub": "test"}
    try:
        reponse = TestClient(main.app).post("/apply_mtu_clamping")
    finally:
        main.app.dependency_overrides.clear()
    assert reponse.status_code == 200 and reponse.json()["success"] is True
    cmd, entree = appels[-1]
    assert cmd[0] == "nft" and cmd[-1] == "-"
    assert "maxseg size set rt mtu" in entree                   # serrage au PMTU, comme avant
    assert "delete table inet secubox_netmodes_mss" in entree   # recréée à chaque appel : jamais de règle en double
    assert "hook forward" in entree
