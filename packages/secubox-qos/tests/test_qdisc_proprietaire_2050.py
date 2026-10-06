# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""#2050 : qos ne touche pas au qdisc racine d'une interface pilotée par traffic."""
from unittest import mock

from secubox_core import qdisc


def _appel(monkeypatch, tmp_path, deja):
    monkeypatch.setenv("SECUBOX_QDISC_DIR", str(tmp_path))
    if deja:
        qdisc.claim("eth1", deja)
    from api import main
    with mock.patch.object(main.subprocess, "run") as run:
        run.return_value.returncode = 0
        res = main._apply_htb({"interface": "eth1"}, "eth1")
    return res, run


def test_interface_de_traffic_non_touchee(monkeypatch, tmp_path):
    res, run = _appel(monkeypatch, tmp_path, "traffic")
    run.assert_not_called()
    assert res["skipped"] is True and "traffic" in res["error"]
    assert qdisc.owner("eth1") == "traffic"


def test_interface_libre_reclamee_par_qos(monkeypatch, tmp_path):
    res, run = _appel(monkeypatch, tmp_path, None)
    assert run.called and not res.get("skipped")
    assert qdisc.owner("eth1") == "qos"
