# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Banc commun des tests du nom de nœud (#3821, #3824, #3883) : `secubox-noeud` chargé par son chemin, une box en miniature
(arbres nginx, table sbxwaf, réglages, état, audit ; commandes enregistrées), et un client HTTP minimal."""
import json
import os
import socket
import subprocess
import sys
import urllib.error
import urllib.request
from importlib.machinery import SourceFileLoader
from importlib.util import module_from_spec, spec_from_loader
from pathlib import Path

import pytest

PKG = Path(__file__).resolve().parents[1]
RACINE = PKG.parents[1]
SCRIPT = PKG / "sbin" / "secubox-noeud"
PAGE = PKG / "www" / "noeud" / "index.html"
# Source du moteur et des faces du dé : le Hall (debian/rules de secubox-core les livre sous www/noeud/, #3883).
HALL = RACINE / "packages" / "secubox-webos" / "www" / "hall"
WAF_ROUTE = RACINE / "packages" / "secubox-core" / "usr" / "sbin" / "secubox-waf-route"
DOM = "gk2.secubox.in"


def charger():
    loader = SourceFileLoader("secubox_noeud", str(SCRIPT))
    mod = module_from_spec(spec_from_loader("secubox_noeud", loader))
    loader.exec_module(mod)
    return mod


@pytest.fixture(name="box")
def box_noeud(tmp_path, monkeypatch):
    # Fixture « box » importée par les modules de tests du nœud : elle y masque celle de conftest.py (sessions, #1607).
    """Une box en miniature : arbres nginx, table sbxwaf, réglages, état, audit ; commandes enregistrées."""
    m = charger()
    umask = os.umask(0o022)                       # fichiers d'essai 0644 : jamais inscriptibles par groupe ni autres
    for d in ("etc/nginx/sites-enabled", "etc/nginx/conf.d", "etc/secubox/waf", "var/log/secubox"):
        (tmp_path / d).mkdir(parents=True)
    (tmp_path / "etc/secubox/noeud").mkdir(mode=0o755)     # le dossier root des réglages (#3883)
    routes = tmp_path / "etc/secubox/waf/haproxy-routes.json"
    routes.write_text(json.dumps({"hall.gk2.secubox.in": ["192.168.1.200", 9080]}))
    (tmp_path / "etc/secubox/haproxy.toml").write_text('[vhosts.hall]\ndomain = "hall.gk2.secubox.in"\n')
    monkeypatch.setattr(m, "CONF", str(tmp_path / "etc/nginx/conf.d/secubox-noeud.conf"))
    monkeypatch.setattr(m, "DOSSIERS_NGINX", (str(tmp_path / "etc/nginx/sites-enabled"), str(tmp_path / "etc/nginx/conf.d")))
    monkeypatch.setattr(m, "FORMAT_HOTES", str(tmp_path / "etc/nginx/conf.d/secubox-hosts-log.conf"))
    monkeypatch.setattr(m, "ROUTES", str(routes))
    monkeypatch.setenv("SBX_WAF_ROUTES", str(routes))
    monkeypatch.setattr(m, "REGLAGES", str(tmp_path / "etc/secubox/noeud/noeud.toml"))
    monkeypatch.setattr(m, "WEBOS_TOML", str(tmp_path / "etc/secubox/webos.toml"))
    monkeypatch.setattr(m, "PROPRIO", os.geteuid())   # « root » de la box miniature : l'utilisateur des tests
    monkeypatch.setattr(m, "HAPROXY_TOML", str(tmp_path / "etc/secubox/haproxy.toml"))
    monkeypatch.setattr(m, "ETAT_DIR", str(tmp_path / "var/lib/secubox-noeud"))
    monkeypatch.setattr(m, "ETAT", str(tmp_path / "var/lib/secubox-noeud/etat.json"))
    monkeypatch.setattr(m, "AUDIT", str(tmp_path / "var/log/secubox/audit.log"))
    monkeypatch.setattr(m, "domaine", lambda: DOM)
    monkeypatch.setattr(m, "mot_de_passe_change", lambda: True)
    m.appels = []
    m.nginx_ok = True
    m.sonde = None

    def executer(argv, delai=60):
        m.appels.append(list(argv))
        if argv[:2] == ["nginx", "-t"] and not m.nginx_ok:
            raise subprocess.CalledProcessError(1, argv, "", "emerg")
        if argv[0] == "secubox-waf-route":       # le VRAI outil de secubox-core, sur la table de la box miniature
            return subprocess.run([sys.executable, "-I", str(WAF_ROUTE), *argv[1:]], check=True, timeout=delai,
                                  capture_output=True, text=True)
        if argv[:3] == ["haproxyctl", "vhost", "add"]:  # haproxyctl écrit sa table
            with open(m.HAPROXY_TOML, "a") as fh:
                fh.write(f'[vhosts.x]\ndomain = "{argv[3]}"\nbackend = "{argv[4]}"\n')
        return subprocess.CompletedProcess(argv, 0, "", "")
    monkeypatch.setattr(m, "executer", executer)
    monkeypatch.setattr(m, "sonder", lambda ip, port, dom: m.sonde)
    m.racine = tmp_path
    yield m
    os.umask(umask)


def table(m):
    return json.loads(Path(m.ROUTES).read_text())


def conf(m):
    p = Path(m.CONF)
    return p.read_text() if p.exists() else None


def audits(m):
    p = Path(m.AUDIT)
    return [json.loads(x) for x in p.read_text().splitlines()] if p.exists() else []


def port_libre():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def get(url, hote):
    req = urllib.request.Request(url, headers={"Host": hote})
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.status, dict(r.headers), r.read()
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read()
