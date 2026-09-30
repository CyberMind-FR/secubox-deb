# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""secubox-lxcctl : le seul passage sudo vers les commandes lxc (#1785).

Il remplace des règles `lxc-start`/`lxc-attach`… à argument libre, dont
`lxc-start -f <configuration>` faisait exécuter des crochets en root sur
l'hôte. On vérifie ce qu'il REFUSE, et l'argv exact qu'il exécute pour
chacun des appelants réels (streamlit, watchdog, vm).
"""
import importlib.machinery
import importlib.util
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "usr" / "sbin" / "secubox-lxcctl"


def _module():
    loader = importlib.machinery.SourceFileLoader("secubox_lxcctl", str(SCRIPT))
    spec = importlib.util.spec_from_loader("secubox_lxcctl", loader)
    m = importlib.util.module_from_spec(spec)
    loader.exec_module(m)
    return m


@pytest.fixture
def ctl(tmp_path, monkeypatch):
    m = _module()
    racine = tmp_path / "lxc"
    for nom in ("streamlit", "web.1"):
        (racine / nom).mkdir(parents=True)
        (racine / nom / "config").write_text("lxc.uts.name = x\n")
    monkeypatch.setattr(m, "CHEMINS", (str(racine),))
    monkeypatch.setattr(m, "lxcpath_defaut", lambda: str(racine))
    lances = []

    def _execv(chemin, argv):
        lances.append(argv)
        raise SystemExit(0)
    monkeypatch.setattr(m.os, "execv", _execv)
    return m, str(racine), lances


def _lancer(m, *argv):
    with pytest.raises(SystemExit) as e:
        m.main(list(argv))
    return e.value.code


@pytest.mark.parametrize("argv", [
    ("lxc-attach", "-n", "streamlit", "--", "sh"),
    ("lxc-destroy", "-n", "streamlit"),
    ("lxc-start", "-n", "streamlit", "-f", "/tmp/piege.conf"),
    ("lxc-start", "-n", "streamlit", "--define", "lxc.hook.pre-start=/tmp/x"),
    ("lxc-start", "-n", "streamlit", "-s", "lxc.hook.pre-start=/tmp/x"),
    ("lxc-start", "-n", "streamlit", "-F"),
    ("lxc-start", "-n", "../streamlit"),
    ("lxc-start", "-n", "inconnu"),
    ("lxc-start", "-n", "streamlit", "-n", "web.1"),
    ("lxc-info", "-P", "/tmp", "-n", "streamlit"),
    ("lxc-info",),
    ("lxc-ls", "-F", "NAME;id"),
    ("lxc-stop", "-n", "streamlit", "-t", "99999"),
    (),
])
def test_refuse(ctl, argv):
    m, _, lances = ctl
    assert _lancer(m, *argv) == 64, argv
    assert lances == []


def test_appel_streamlit(ctl):
    m, r, lances = ctl
    assert _lancer(m, "lxc-info", "-n", "streamlit", "-s") == 0
    assert lances == [["/usr/bin/lxc-info", "-P", r, "-s", "-n", "streamlit"]]


def test_appels_watchdog(ctl):
    m, r, lances = ctl
    _lancer(m, "lxc-info", "-P", r, "-n", "web.1", "-s", "-p")
    _lancer(m, "lxc-ls", "-P", r, "-f")
    _lancer(m, "lxc-start", "-P", r, "-n", "web.1", "-d")
    assert lances == [
        ["/usr/bin/lxc-info", "-P", r, "-s", "-p", "-n", "web.1"],
        ["/usr/bin/lxc-ls", "-P", r, "-f"],
        ["/usr/bin/lxc-start", "-P", r, "-d", "-n", "web.1"],
    ]


def test_appels_vm(ctl):
    m, r, lances = ctl
    _lancer(m, "lxc-ls", "-f", "-F", "NAME,STATE,IPV4,RAM,AUTOSTART")
    _lancer(m, "lxc-stop", "-n", "streamlit", "-k")
    _lancer(m, "lxc-freeze", "-n", "streamlit")
    assert lances == [
        ["/usr/bin/lxc-ls", "-P", r, "-f", "-F", "NAME,STATE,IPV4,RAM,AUTOSTART"],
        ["/usr/bin/lxc-stop", "-P", r, "-k", "-n", "streamlit"],
        ["/usr/bin/lxc-freeze", "-P", r, "-n", "streamlit"],
    ]


def test_python_isole():
    assert SCRIPT.read_text().splitlines()[0] == "#!/usr/bin/python3 -I"
