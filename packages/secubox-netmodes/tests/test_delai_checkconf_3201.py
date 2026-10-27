# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3201 — gk2 (2026-10-27) : l'application du panneau a échoué sur « unbound-checkconf refuse la configuration DNS :
délai de 120 s dépassé ». 101 Mo de listes de blocage dans unbound.conf.d sur une box saturée : la validation dépasse le
délai commun de 120 s. unbound-checkconf a son propre délai, et un dépassement se dit comme tel, jamais « refuse »."""
import subprocess
from types import SimpleNamespace

import pytest

from api import routeur_ctl as rc


def _capturer(monkeypatch, effet=None):
    vus = []

    def faux_run(argv, **kw):
        vus.append(kw.get("timeout"))
        if effet is not None:
            raise effet(argv, kw.get("timeout"))
        return subprocess.CompletedProcess(argv, 0, "", "")

    monkeypatch.setattr(rc.subprocess, "run", faux_run)
    return vus


def test_checkconf_a_son_propre_delai(monkeypatch):
    vus = _capturer(monkeypatch)
    rc.executer_systeme(["unbound-checkconf"])
    rc.executer_systeme(["nft", "-c", "-f", "/x.nft"])
    assert vus == [rc.DELAI_UNBOUND_MAX, 120]
    assert rc.DELAI_UNBOUND_MAX >= 600


def test_delai_depasse_cite_le_vrai_delai(monkeypatch):
    _capturer(monkeypatch, subprocess.TimeoutExpired)
    r = rc.executer_systeme(["unbound-checkconf"])
    assert r.returncode == 124
    assert f"délai de {rc.DELAI_UNBOUND_MAX:g} s dépassé" in r.stderr


def test_validation_hors_delai_ne_dit_pas_refuse():
    def executer(argv):
        if argv[0] == "unbound-checkconf":
            return subprocess.CompletedProcess(argv, 124, "", "délai de 900 s dépassé")
        return subprocess.CompletedProcess(argv, 0, "", "")

    ctx = SimpleNamespace(executer=executer, racine=rc.Path("/"))
    with pytest.raises(rc.Refus) as exc:
        rc._valider(ctx, geo=False)
    message = str(exc.value)
    assert "refuse" not in message
    assert "n'a pas fini" in message and "900 s" in message


def test_validation_refusee_reste_un_refus():
    def executer(argv):
        if argv[0] == "unbound-checkconf":
            return subprocess.CompletedProcess(argv, 1, "", "syntax error")
        return subprocess.CompletedProcess(argv, 0, "", "")

    ctx = SimpleNamespace(executer=executer, racine=rc.Path("/"))
    with pytest.raises(rc.Refus, match="unbound-checkconf refuse la configuration DNS : syntax error"):
        rc._valider(ctx, geo=False)
