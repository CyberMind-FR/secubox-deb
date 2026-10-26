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
    # C1 : les parents partagés ne sont créés que s'ils manquent, dans l'état du socle (secrets : root:secubox 0750).
    assert "[ -d /etc/secubox/secrets ] || install -d -o root -g secubox -m 0750 /etc/secubox/secrets" in p
    assert "[ -d /etc/secubox ] || install -d -m 0755 /etc/secubox" in p
    assert not re.search(r"^\s*install -d [^\n]*/etc/secubox(/secrets)?$", p, re.M)
    assert "install -d -o root -g root -m 0700 /etc/secubox/secrets/meet" in p


def test_control_depend_d_openssl():
    """m2 : install-lxc.sh tire les secrets par `openssl rand`."""
    depends = (RACINE / "debian" / "control").read_text().split("Depends:", 1)[1].split("Recommends:", 1)[0]
    assert re.search(r"^\s*openssl,?$", depends, re.M)
    assert "openssl rand" in (RACINE / "lib" / "meet" / "install-lxc.sh").read_text()


def test_readme_sauvegarde_et_suivi_du_provisionnement():
    """m6 : pg_dump par runuser (le conteneur n'a pas sudo), suivi par le journal de l'unité."""
    r = (RACINE / "README.md").read_text()
    assert "lxc-attach -n meet -P /data/lxc -- runuser -u postgres -- pg_dump meet" in r
    assert "journalctl -u secubox-meet-provision" in r and "sudo -u postgres" not in r


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


def test_profil_apparmor_couvre_ce_que_lit_l_authentification():
    p = (RACINE / "apparmor" / "secubox-meet").read_text()
    for regle in ("/etc/secubox/users.json r,", "/etc/secubox/appareils.json r,", "/etc/secubox/secubox.conf r,",
                  "/etc/secubox/auth.toml r,", "/var/lib/secubox/auth/** r,",
                  "/var/log/secubox/delegation.log w,", "/var/log/secubox/garde-origine.log w,"):
        assert regle in p, regle


def test_vhosts_servent_les_pages_d_erreur_secubox():
    # Conteneur arrêté ou en cours de provisionnement : la page d'erreur SecuBox, pas celle de nginx par défaut.
    # Pas le snippet « réveil » : il active proxy_intercept_errors (les erreurs JSON de l'API de Meet deviendraient
    # du HTML) et sert aux modules à la demande, ce que Meet n'est pas.
    for vhost in (VISIO, LIVEKIT):
        t = vhost.read_text()
        assert "include snippets/secubox-errorpages.conf;" in t
        assert "secubox-waking.conf" not in t and "proxy_intercept_errors on" not in t


def test_versions_annoncees_suivent_le_changelog():
    # meetctl et l'API annonçaient encore 0.1.1 avec le paquet 0.1.5 installé (gk1).
    amont = re.match(r"secubox-meet \((\d+\.\d+\.\d+)-", (RACINE / "debian/changelog").read_text()).group(1)
    assert f'readonly VERSION="{amont}"' in (RACINE / "sbin/meetctl").read_text()
    assert f'VERSION = "{amont}"' in (RACINE / "api/main.py").read_text()


# ── #3182 : activité de la visio ────────────────────────────────────────────────────────────────────────────────────
def test_sudoers_accorde_les_seuls_verbes_d_activite_de_l_api():
    s = (RACINE / "debian" / "secubox-meet.sudoers").read_text()
    for ligne in ("/usr/sbin/meetctl en-direct", "/usr/sbin/meetctl reunions", "/usr/sbin/meetctl clore *"):
        assert ligne in s
    assert "meetctl activite-collecte" not in s                       # la minuterie tourne en root, jamais l'API


def test_minuterie_de_releve_toutes_les_cinq_minutes():
    svc = (RACINE / "debian" / "secubox-meet-activite.service").read_text()
    tim = (RACINE / "debian" / "secubox-meet-activite.timer").read_text()
    assert "ExecStart=/usr/sbin/meetctl activite-collecte" in svc and "Type=oneshot" in svc
    assert "OnUnitActiveSec=5min" in tim and "OnActiveSec=" in tim and "WantedBy=timers.target" in tim   # #2919
    regles = (RACINE / "debian" / "rules").read_text()
    assert "debian/*.timer" in regles
    post = (RACINE / "debian" / "postinst").read_text()
    assert "systemctl enable --now secubox-meet-activite.timer" in post
    pre = (RACINE / "debian" / "prerm").read_text()
    assert "secubox-meet-activite.timer" in pre


def test_profil_apparmor_lit_la_base_d_activite_sans_l_ecrire():
    p = (RACINE / "apparmor" / "secubox-meet").read_text()
    # k : SQLite pose des verrous même en lecture ; sans lui, « database is locked » sous AppArmor (gk1)
    assert "/var/lib/secubox-meet/activite.db rk," in p and "/var/lib/secubox-meet/activite.db-journal r," in p
    assert "/var/lib/secubox-meet/** w" not in p and "activite.db rw" not in p and "/var/lib/secubox/meet/" not in p


def test_base_d_activite_sous_un_parent_de_root_et_migration_postinst():
    """Relecture #3182 : /var/lib/secubox appartient au compte partagé secubox, qui pouvait y glisser un lien sous les
    écritures root. La base vit sous /var/lib/secubox-meet (parent /var/lib, root)."""
    post = (RACINE / "debian" / "postinst").read_text()
    assert "install -d -m 0750 -o root -g secubox /var/lib/secubox-meet" in post
    assert "/var/lib/secubox/meet" in post and '[ ! -L /var/lib/secubox/meet ]' in post
    assert 'readonly ACTIVITE_DB="${SECUBOX_MEET_ACTIVITE_DB:-/var/lib/secubox-meet/activite.db}"' in (RACINE / "sbin" / "meetctl").read_text()


def test_unite_de_releve_durcie():
    svc = (RACINE / "debian" / "secubox-meet-activite.service").read_text()
    for ligne in ("UMask=0027", "ProtectSystem=strict", "ReadWritePaths=/var/lib/secubox-meet /var/log/secubox",
                  "PrivateTmp=yes", "ProtectHome=yes", "NoNewPrivileges=yes", "ProtectKernelTunables=yes", "ProtectControlGroups=yes"):
        assert ligne in svc, ligne
