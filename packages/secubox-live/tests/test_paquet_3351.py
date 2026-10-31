# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""secubox-live (#3351) : page publique, API en lecture seule, unités durcies, exposition seulement sur domaine configuré."""
import json
import re
import subprocess
import sys
from pathlib import Path

ICI = Path(__file__).resolve().parent.parent
DEPOT = ICI.parent.parent
sys.path.insert(0, str(ICI))


def lire(rel: str) -> str:
    return (ICI / rel).read_text()


def test_carte_identique_a_la_prod():
    prod = (DEPOT / "packages/secubox-metrics/www/metrics/index.html").read_text()
    js = lire("www/live/carte.js")
    for nom in ("TERRE", "CENTRE"):
        motif = r'var TERRE="[^"]*";' if nom == "TERRE" else r"var CENTRE=\{[^}]*\};"
        assert re.search(motif, prod).group(0) in js, nom


def test_page_sans_innerhtml_ni_script_integre():
    js = lire("www/live/live.js")
    assert "innerHTML" not in js and "eval(" not in js
    html = lire("www/live/index.html")
    assert re.search(r"<script>", html) is None                       # aucun script intégré
    assert re.search(r"\son[a-z]+=", html) is None                    # aucun gestionnaire d'événement intégré
    assert "style=" not in html


def test_csp_stricte_et_seule_route_d_api():
    conf = lire("nginx/live.vhost.conf")
    csp = re.search(r'Content-Security-Policy "([^"]*)"', conf).group(1)
    assert "unsafe-inline" not in csp and "script-src 'self'" in csp and "frame-ancestors 'none'" in csp
    assert re.findall(r"location = /api/v1/live/([a-z]+)", conf) == ["etat"]
    assert "limit_except GET" in conf and 'proxy_set_header Cookie ""' in conf
    assert "location / { return 404; }" in conf


def test_unites_durcies_compte_dedie():
    for u in ("systemd/secubox-live.service", "systemd/secubox-live-collecte.service"):
        s = lire(u)
        assert "User=secubox-live" in s and "NoNewPrivileges=true" in s and "ProtectSystem=strict" in s
        assert "CapabilityBoundingSet=\n" in s
    assert "RestrictAddressFamilies=AF_UNIX\n" in lire("systemd/secubox-live.service")
    ap = lire("apparmor/secubox-live")
    assert "deny /etc/secubox/secrets/** r" in ap and "/usr/sbin/secubox-live-api {" in ap and "/usr/sbin/secubox-live-collecte {" in ap


def test_exposition_seulement_avec_un_domaine(tmp_path):
    s = lire("sbin/secubox-live-exposer")
    conf = lire("conf/live.toml")
    assert re.search(r'^domaine = ""$', conf, re.M)          # rien d'exposé par défaut
    assert "nginx -t" in s and s.index("nginx -t") < s.index("secubox-waf-route") < s.index("haproxyctl vhost add")
    assert "live.*.*" in s


def test_api_lit_le_fichier_et_rend_503_sans(tmp_path, monkeypatch):
    from fastapi.testclient import TestClient
    import api.main as M
    monkeypatch.setattr(M, "ETAT", tmp_path / "etat.json")
    M._cache.update(mtime=None, doc=None)
    cli = TestClient(M.app)
    assert cli.get("/etat").status_code == 503
    (tmp_path / "etat.json").write_text(json.dumps({"version": 1, "genere_le": 1}))
    r = cli.get("/etat")
    assert r.status_code == 200 and r.json()["version"] == 1
    assert cli.post("/etat").status_code == 405


def test_spdx_et_versions():
    for p in ICI.rglob("*"):
        if p.is_file() and p.suffix in (".py", ".js", ".css", ".conf", ".toml", ".service", ".timer") and "__pycache__" not in p.parts:
            assert "SPDX-License-Identifier" in p.read_text()[:400], p
    assert lire("debian/changelog").startswith("secubox-live (0.1.0-1~trixie1) trixie;")
    assert lire("debian/compat").strip() == "13" and "Standards-Version: 4.6.2" in lire("debian/control")
    for sh in ("debian/postinst", "debian/prerm", "debian/postrm", "sbin/secubox-live-exposer"):
        assert subprocess.run(["sh", "-n", str(ICI / sh)]).returncode == 0, sh
