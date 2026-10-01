# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""Les domaines dont la box a besoin échappent au puits DNS (#1819)."""
import importlib.machinery
import importlib.util
import pathlib
import sys
import types

SCRIPT = pathlib.Path(__file__).resolve().parents[1] / "sbin" / "secubox-adblock-sync"


def _module(tmp_path, monkeypatch):
    # le script importe le compilateur de listes (secubox-toolbox) : un faux
    # suffit pour _render
    faux = types.ModuleType("secubox_toolbox")
    faux.filterlists = types.ModuleType("secubox_toolbox.filterlists")
    monkeypatch.setitem(sys.modules, "secubox_toolbox", faux)
    monkeypatch.setitem(sys.modules, "secubox_toolbox.filterlists", faux.filterlists)
    loader = importlib.machinery.SourceFileLoader("adblock_sync", str(SCRIPT))
    spec = importlib.util.spec_from_loader("adblock_sync", loader)
    m = importlib.util.module_from_spec(spec)
    loader.exec_module(m)
    monkeypatch.setattr(m, "DOMAIN_ALLOWLIST", tmp_path / "domain-allowlist.txt")
    monkeypatch.setattr(m, "IP_ALLOWLIST", tmp_path / "ip-allowlist.txt")
    return m


def test_db_ip_reste_resolu_sous_un_parent_bloque(tmp_path, monkeypatch):
    m = _module(tmp_path, monkeypatch)
    conf = m._render(["db-ip.com", "pisteur.example"])
    assert 'local-zone: "db-ip.com." always_nxdomain' in conf
    assert 'local-zone: "download.db-ip.com." always_transparent' in conf
    assert 'local-zone: "pisteur.example." always_nxdomain' in conf


def test_un_exempte_bloque_exactement_n_est_pas_double(tmp_path, monkeypatch):
    m = _module(tmp_path, monkeypatch)
    conf = m._render(["download.db-ip.com"])
    assert conf.count('"download.db-ip.com."') == 1, "deux local-zone du même nom : unbound refuse"


def test_liste_d_administration(tmp_path, monkeypatch):
    m = _module(tmp_path, monkeypatch)
    (tmp_path / "domain-allowlist.txt").write_text("# commentaire\nExemple.ORG.\nmauvais nom!\n")
    conf = m._render(["exemple.org"])
    assert 'local-zone: "exemple.org." always_transparent' in conf
    assert "always_nxdomain" not in conf and "mauvais" not in conf
