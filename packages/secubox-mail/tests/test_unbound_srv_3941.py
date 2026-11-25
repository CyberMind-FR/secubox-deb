# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""SRV de messagerie dans Unbound (#3941) : rien si identique, checkconf puis fast_reload, jamais de redémarrage."""
import importlib.util
import sys
from pathlib import Path

import pytest

PAQUET = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PAQUET.parents[1] / "common"))
spec = importlib.util.spec_from_file_location("unbound_srv", PAQUET / "lib" / "mail" / "unbound_srv.py")
M = importlib.util.module_from_spec(spec)
spec.loader.exec_module(M)


class Faux(M.SystemeUnbound):
    def __init__(self, conf_ok=True, recharge_ok=True):
        self.appels, self.conf_ok, self.recharge_ok = [], conf_ok, recharge_ok

    def verifier_unbound(self):
        self.appels.append("checkconf")
        return self.conf_ok, "erreur"

    def recharger_unbound(self):
        self.appels.append("recharge")
        if not self.recharge_ok:
            raise self.ERREUR("refus")


@pytest.fixture
def f(tmp_path):
    src, dst = tmp_path / "src.conf", tmp_path / "conf.d" / "97-mail-srv.conf"
    dst.parent.mkdir()
    src.write_text("server:\n")
    return src, dst


def test_identique_rien(f):
    src, dst = f
    dst.write_text(src.read_text())
    s = Faux()
    assert M.poser(src, dst, True, s) == "inchange" and s.appels == []


def test_change_verifie_puis_recharge(f):
    src, dst = f
    s = Faux()
    assert M.poser(src, dst, True, s) == "applique" and s.appels == ["checkconf", "recharge"]
    assert dst.read_text() == "server:\n" and dst.stat().st_mode & 0o777 == 0o644


def test_unbound_arrete_pose_sans_recharger(f):
    s = Faux()
    assert M.poser(*f, False, s) == "ecrit" and s.appels == ["checkconf"]


@pytest.mark.parametrize("s", [Faux(conf_ok=False), Faux(recharge_ok=False)])
def test_refus_ancien_contenu_remis(f, s):
    src, dst = f
    dst.write_text("ancien\n")
    with pytest.raises(M.ErreurUnbound):
        M.poser(src, dst, True, s)
    assert dst.read_text() == "ancien\n"


def test_postinst_sans_redemarrage_d_unbound():
    pi = "\n".join(x for x in (PAQUET / "debian" / "postinst").read_text().splitlines() if not x.lstrip().startswith("#"))
    assert "unbound_srv.py" in pi
    for interdit in ("restart unbound", "reload unbound", "unbound-control"):
        assert interdit not in pi
    assert "secubox-core (>= 1.8.38~)" in (PAQUET / "debian" / "control").read_text()
    assert "restart" not in (PAQUET / "lib" / "mail" / "unbound_srv.py").read_text()
