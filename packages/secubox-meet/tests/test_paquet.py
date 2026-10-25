# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Paquet secubox-meet : vhosts, routes, scripts de maintenance (#3154)."""
import re
import subprocess
from pathlib import Path

RACINE = Path(__file__).resolve().parents[1]
VISIO = RACINE / "nginx" / "visio-vhost.conf"
LIVEKIT = RACINE / "nginx" / "livekit-vhost.conf"
ROUTES = RACINE / "nginx" / "meet-routes.conf"
POSTINST = RACINE / "debian" / "postinst"
PRERM = RACINE / "debian" / "prerm"
POSTRM = RACINE / "debian" / "postrm"


def test_vhosts_jokers_et_websocket():
    v, l = VISIO.read_text(), LIVEKIT.read_text()
    assert "server_name visio.*;" in v and "server_name livekit.*;" in l and "listen 9080;" in v and "listen 9080;" in l
    for t in (v, l):
        assert "proxy_set_header Upgrade $http_upgrade" in t and "X-Forwarded-Proto https" in t and not re.search(r"gk\d", t)
    assert "proxy_pass http://10.100.0.195:80;" in v and "proxy_pass http://10.100.0.195:7880;" in l


def test_vhosts_delais_en_tetes_et_pas_de_csp():
    v, l = VISIO.read_text(), LIVEKIT.read_text()
    assert "proxy_read_timeout 900s" in v and "client_max_body_size 50m" in v
    assert "proxy_read_timeout 3600s" in l and "proxy_buffering off" in l
    for t in (v, l):
        assert "X-Content-Type-Options" in t and "Referrer-Policy" in t and "X-Robots-Tag" in t
        assert "Content-Security-Policy" not in t and "frame-ancestors" not in t


def test_routes_api_et_page():
    r = ROUTES.read_text()
    assert "location /api/v1/meet/" in r and "proxy_pass http://unix:/run/secubox/meet.sock;" in r
    assert "rewrite ^/api/v1/meet/(.*)$ /$1 break;" in r
    assert "location /meet/" in r and "alias /usr/share/secubox/www/meet/;" in r


def test_postinst_waf_et_haproxy_apres_nginx_t_et_provision_apres_debhelper():
    p = POSTINST.read_text()
    assert p.index("nginx -t") < p.index("secubox-waf-route") < p.index("haproxyctl vhost add") and "sbxwaf_inspector" in p
    assert p.index("#DEBHELPER" + "#") < p.index("secubox-meet-provision.service")
    assert "media-expose --apply" not in p and "nft -f" not in p          # jamais d'ouverture par apt install


def test_postinst_dossiers_et_droits():
    p = POSTINST.read_text()
    for m in ("/etc/secubox/meet", "/etc/secubox/secrets/meet", "/var/cache/secubox/meet", "ports-publics.d",
              "visudo -cf /etc/sudoers.d/secubox-meet", "meet.toml.example"):
        assert m in p
    assert not re.search(r"gk\d", p)


def test_prerm_arrete_et_revoque():
    p = PRERM.read_text()
    assert "secubox-meet-provision.service" in p and "media-expose --revoke" in p and "meetctl stop" in p


def test_postrm_purge_retire_les_secrets_mais_jamais_le_conteneur():
    p = POSTRM.read_text()
    assert "secrets/meet" in p and "client-rm meet" in p and "lxc-destroy" not in p and "/data/lxc" not in p
    assert "ports-publics.d/meet.json" in p


def test_scripts_de_maintenance_valides():
    for f in (POSTINST, PRERM, POSTRM): assert subprocess.run(["bash", "-n", f]).returncode == 0
    assert "DEBHELPER" not in "".join(l for l in POSTINST.read_text().splitlines() if l.strip().startswith("#") and l.strip() != "#DEBHELPER" + "#")


def test_postinst_ne_demarre_pas_l_api_sans_profil_charge():
    t = POSTINST.read_text()
    charge = t.index("apparmor_parser -r /etc/apparmor.d/secubox-meet")
    msg = t.index("profil AppArmor secubox-meet-api non chargé")
    demarre = t.index("systemctl enable --now secubox-meet.service")
    assert charge < msg < demarre
    assert 'PROFIL_PRET=0' in t and '[ "$PROFIL_PRET" = 1 ]' in t and "journalctl -k" in t
    assert "systemctl enable secubox-meet.service" in t
