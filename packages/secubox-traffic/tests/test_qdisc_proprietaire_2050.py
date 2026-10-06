# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""#2050 : traffic ne supprime ni ne remplace le qdisc racine d'une interface pilotée par qos."""
from unittest import mock

from secubox_core import qdisc


def _applique(monkeypatch, tmp_path, config, deja=None, existantes=("eth1", "eth2")):
    monkeypatch.setenv("SECUBOX_QDISC_DIR", str(tmp_path))
    for iface, mod in (deja or {}).items():
        qdisc.claim(iface, mod)
    from api import main
    cmds = []

    def faux(cmd, *a, **k):
        cmds.append(cmd)
        return True, "", ""

    with mock.patch.object(main, "run_cmd", faux), \
            mock.patch.object(main, "get_shaped_interfaces", lambda: list(existantes)):
        main.apply_tc_config(config)
    return cmds


def test_interface_de_qos_laissee_intacte(monkeypatch, tmp_path):
    cfg = {"classes": [{"interface": "eth1"}, {"interface": "eth2"}]}
    cmds = _applique(monkeypatch, tmp_path, cfg, deja={"eth1": "qos"})
    touchees = {c[4] for c in cmds if c[:3] in (["tc", "qdisc", "del"], ["tc", "qdisc", "add"])}
    assert "eth1" not in touchees
    assert "eth2" in touchees
    assert qdisc.owner("eth1") == "qos"
    assert qdisc.owner("eth2") == "traffic"


def test_effacement_ne_libere_que_ce_qui_est_a_traffic(monkeypatch, tmp_path):
    monkeypatch.setenv("SECUBOX_QDISC_DIR", str(tmp_path))
    qdisc.claim("eth1", "qos")
    qdisc.claim("eth2", "traffic")
    from api import main
    cmds = []
    with mock.patch.object(main, "run_cmd", lambda c, *a, **k: (cmds.append(c), (True, "", ""))[1]), \
            mock.patch.object(main, "get_shaped_interfaces", lambda: ["eth1", "eth2"]), \
            mock.patch.object(main.stats_cache, "invalidate", lambda: None), \
            mock.patch.object(main, "add_event", lambda *a, **k: None):
        import asyncio
        asyncio.run(main.clear_shaping())
    assert [c[4] for c in cmds] == ["eth2"]
    assert qdisc.owner("eth1") == "qos" and qdisc.owner("eth2") is None
