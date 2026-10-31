# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""secubox-live (#3351) : page publique servie en statique, unités durcies, exposition seulement sur domaine configuré."""
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


def test_vhost_statique_local_nom_exact_hsts():
    conf = lire("nginx/live.vhost.conf.in")
    csp = re.search(r'Content-Security-Policy "([^"]*)"', conf).group(1)
    assert "unsafe-inline" not in csp and "script-src 'self'" in csp and "frame-ancestors 'none'" in csp
    assert "listen 127.0.0.1:9080;" in conf and "server_name @DOMAINE@;" in conf and "live.*" not in conf
    assert conf.count("Strict-Transport-Security") == 2                      # reposé dans la location etat.json
    assert "alias /var/cache/secubox/live/etat.json;" in conf and "expires 15s;" in conf
    assert "proxy_pass" not in conf and "/api/" not in conf                  # aucune API par requête
    assert "limit_except GET HEAD" in conf and "location / { return 404; }" in conf


def test_unites_durcies_compte_dedie_sans_groupe_secubox():
    s = lire("systemd/secubox-live-collecte.service")
    assert "User=secubox-live" in s and "NoNewPrivileges=true" in s and "ProtectSystem=strict" in s
    assert "CapabilityBoundingSet=\n" in s
    assert re.search(r"^SupplementaryGroups=secubox-pilotage$", s, re.M)
    assert not (ICI / "systemd/secubox-live.service").exists() and not (ICI / "api").exists()
    ap = lire("apparmor/secubox-live")
    assert "deny /etc/secubox/secrets/** r" in ap and "secubox-live-api" not in ap
    assert "pilotage.db-shm" in ap and "pilotage.db-wal" in ap and "dpi" not in ap
    post = lire("debian/postinst")
    assert "setfacl -m u:secubox-live:rx" in post and "secubox-live.service" not in post


def test_exposition_seulement_avec_un_domaine_et_sous_garde():
    s = lire("sbin/secubox-live-exposer")
    conf = lire("conf/live.toml")
    assert re.search(r'^domaine = ""$', conf, re.M) and re.search(r"^noeuds_publics = \[\]$", conf, re.M)
    assert s.index("/sys/kernel/security/apparmor/profiles") < s.index("NT=$(nginx -t") < s.index("! secubox-waf-route") < s.index("haproxyctl vhost add")
    garde = s[s.index("! secubox-waf-route"):s.index("haproxyctl vhost add")]
    assert "retirer" in garde and "exit 1" in garde                             # route WAF en échec : rien d'exposé
    assert "(enforce)" in s and "@DOMAINE@" in s


def test_exposer_refuse_un_domaine_douteux(tmp_path):
    s = lire("sbin/secubox-live-exposer")
    motif = re.search(r"grep -Eqx '([^']+)'", s).group(1)
    for bon in ("live.secubox.in", "live.gk2.secubox.in"):
        assert subprocess.run(["grep", "-Eqx", motif], input=bon, text=True).returncode == 0, bon
    for mauvais in ("secubox.in", "live.in", "live.a;b.in", "x.live.secubox.in"):
        assert subprocess.run(["grep", "-Eqx", motif], input=mauvais, text=True).returncode != 0, mauvais


def test_spdx_et_versions():
    for p in ICI.rglob("*"):
        if p.is_file() and p.suffix in (".py", ".js", ".css", ".conf", ".in", ".toml", ".service", ".timer") and "__pycache__" not in p.parts:
            assert "SPDX-License-Identifier" in p.read_text()[:400], p
    assert lire("debian/changelog").startswith("secubox-live (0.1.0-1~trixie1) trixie;")
    assert lire("debian/compat").strip() == "13" and "Standards-Version: 4.6.2" in lire("debian/control")
    for sh in ("debian/postinst", "debian/prerm", "debian/postrm", "sbin/secubox-live-exposer"):
        assert subprocess.run(["sh", "-n", str(ICI / sh)]).returncode == 0, sh
