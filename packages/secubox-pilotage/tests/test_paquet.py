# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Task 10 (#3126) : le paquet secubox-pilotage — unité durcie, AppArmor, postinst, nginx, menu, agrégateur, CI."""
import json
import re
import subprocess
from pathlib import Path

ICI = Path(__file__).resolve().parents[1]
DEPOT = ICI.parents[1]


def lire(rel: str, base: Path = ICI) -> str:
    return (base / rel).read_text(encoding="utf-8")


def code(rel: str) -> str:
    """Le fichier sans ses lignes de commentaire."""
    return "\n".join(x for x in lire(rel).splitlines() if not x.lstrip().startswith("#"))


def test_unite_maitre_durcie():
    u = lire("systemd/secubox-pilotage.service")
    for ligne in ("User=secubox-pilotage", "NoNewPrivileges=yes", "ProtectSystem=strict", "ProtectHome=yes", "PrivateTmp=yes",
                  "ProtectKernelTunables=yes", "ProtectKernelModules=yes", "ProtectControlGroups=yes", "RestrictSUIDSGID=yes",
                  "LockPersonality=yes", "RestrictNamespaces=yes", "CapabilityBoundingSet=", "UMask=0027", "LimitCORE=0"):
        assert ligne in u, ligne
    assert "ExecStart=/usr/sbin/secubox-pilotage-api" in u
    assert "User=root" not in u
    # le SEUL emplacement d'écriture : données, audit et sockets
    rw = re.search(r"^ReadWritePaths=(.*)$", u, re.M).group(1).split()
    assert set(rw) == {"/var/lib/secubox/pilotage", "/var/log/secubox", "/run/secubox"}
    # sockets périmées d'un autre propriétaire dans /run/secubox (collant) : retirées en root avant le démarrage
    assert "ExecStartPre=+/bin/rm -f /run/secubox/pilotage.sock /run/secubox/pilotage-canal.sock" in u


def test_unite_groupes_des_sockets():
    u = lire("systemd/secubox-pilotage.service")
    assert re.search(r"ExecStartPost=\+.*chgrp www-data /run/secubox/pilotage-canal\.sock", u)
    assert re.search(r"ExecStartPost=\+.*chgrp secubox /run/secubox/pilotage\.sock", u)
    assert "0666" not in code("systemd/secubox-pilotage.service")


def test_unite_reseau_unix_seulement():
    u = lire("systemd/secubox-pilotage.service")
    assert "RestrictAddressFamilies=AF_UNIX" in u        # aucun port TCP


def test_profil_apparmor_enforce_et_borne():
    p = lire("apparmor/secubox-pilotage-api")
    assert p.rstrip().endswith("}") and "/usr/sbin/secubox-pilotage-api {" in p
    assert "flags=(complain" not in p and "complain" not in p
    assert "deny /etc/secubox/secrets/** r," in p
    assert "/var/lib/secubox/pilotage/** rwkm," in p
    assert "/run/secubox/pilotage.sock rwk," in p and "/run/secubox/pilotage-canal.sock rwk," in p
    assert "network inet" not in p                         # pas de réseau IP


def test_ecoute_et_declencheurs():
    s = lire("systemd/secubox-pilotage-ecoute.service")
    assert "Type=oneshot" in s and "ExecStart=/usr/sbin/secubox-pilotage-ecoute" in s and "NoNewPrivileges=yes" in s
    chemin = lire("systemd/secubox-pilotage-ecoute.path")
    assert "PathChanged=/var/lib/secubox/p2p/wg_mesh.json" in chemin and "Unit=secubox-pilotage-ecoute.service" in chemin
    assert "PathChanged=/var/lib/secubox/autoload-public/pairs-publics.json" in chemin
    assert "OnUnitInactiveSec=" in lire("systemd/secubox-pilotage-ecoute.timer")
    # la rotation du journal (create 0640 secubox) fait perdre l'ACL du service : l'unité root la repose à chaque passage
    assert "setfacl -m u:secubox-pilotage:rw- /var/log/secubox/audit.log" in s


def test_nginx_administration_derriere_le_chemin_normal():
    c = lire("nginx/pilotage.conf")
    assert "location /api/v1/pilotage/" in c
    assert "proxy_pass http://unix:/run/secubox/pilotage.sock;" in c
    assert "pilotage-canal" not in c and "8472" not in c            # l'administration n'est jamais sur une IP de tunnel


def test_modele_du_canal_pose_x_real_ip():
    t = lire("nginx/pilotage-canal.conf.tpl")
    assert "proxy_set_header X-Real-IP $remote_addr;" in t
    assert "proxy_set_header X-Forwarded-For $remote_addr;" in t
    assert "include /etc/nginx/snippets/secubox-proxy.conf" not in t   # un seul auteur de X-Real-IP
    assert "client_max_body_size 256k;" in t and "proxy_read_timeout 60s;" in t


def test_controle_debian():
    c = lire("debian/control")
    assert "Package: secubox-pilotage\n" in c and "Architecture: all" in c and "Standards-Version: 4.6.2" in c
    assert lire("debian/compat").strip() == "13"
    ch = lire("debian/changelog").splitlines()[0]
    assert ch.startswith("secubox-pilotage (0.1.0-1~trixie1) trixie;")


def test_postinst_et_prerm():
    p = lire("debian/postinst")
    assert "systemctl enable --now secubox-pilotage.service" in p
    assert "adduser --system" in p and "secubox-pilotage" in p
    assert "install -d -o secubox-pilotage" in p and "-m 0750 /var/lib/secubox/pilotage" in p
    assert "tmpfiles" not in code("debian/postinst")                                      # systemd-tmpfiles refuse ces chemins
    assert "[ -L /var/lib/secubox/pilotage ]" in p                   # jamais suivre un lien
    assert "setfacl -m u:secubox-pilotage:rw-" in p and "/var/log/secubox/audit.log" in p
    assert "chmod" not in "\n".join(x for x in p.splitlines() if "audit.log" in x)   # les droits du journal ne changent pas
    assert "apparmor_parser -r /etc/apparmor.d/secubox-pilotage-api" in p
    assert "/usr/sbin/secubox-pilotage-ecoute" in p
    assert "systemctl stop secubox-pilotage.service" in lire("debian/prerm")
    for sh in ("debian/postinst", "debian/prerm", "debian/postrm", "sbin/secubox-pilotage-ecoute"):
        assert subprocess.run(["sh" if "ecoute" not in sh else "bash", "-n", str(ICI / sh)]).returncode == 0, sh


def test_menu():
    m = json.loads(lire("menu.d/596-pilotage.json"))
    assert m["id"] == "pilotage" and m["path"] == "/fleet/" and m["category"] == "mesh" and m["order"] == 596 and m["icon"]


def test_spdx_partout():
    for chemin in ICI.rglob("*"):
        if not chemin.is_file() or any(p.startswith(".") or p == "__pycache__" for p in chemin.relative_to(ICI).parts) or chemin.suffix in (".pyc", ".json") or chemin.name in ("compat", "pytest.ini", "control", "changelog", "format"):
            continue
        assert "LicenseRef-CMSD-1.0" in chemin.read_text(encoding="utf-8")[:600], chemin
        assert chemin.name == "test_paquet.py" or "SA" + "SU" not in chemin.read_text(encoding="utf-8"), chemin


def test_pilotage_dans_dedicated_modules():
    main = lire("secubox-aggregator/aggregator/main.py", DEPOT / "packages")
    ligne = re.search(r"DEDICATED_MODULES = frozenset\(\{(.*?)\}\)", main, re.S).group(1)
    assert '"pilotage"' in ligne
    migrate = lire("secubox-aggregator/sbin/secubox-aggregator-migrate", DEPOT / "packages")
    assert "pilotage" in re.search(r'readonly AGG_EXCLUDE="([^"]*)"', migrate).group(1).split()


def test_pilotage_dans_la_matrice_ci():
    y = lire(".github/workflows/backend-tests.yml", DEPOT)
    assert re.search(r"- suite: secubox-pilotage\n\s+chemin: packages/secubox-pilotage/tests", y)
    assert re.search(r"- suite: secubox-pilotage-agent\n\s+module: packages/secubox-pilotage-agent", y)
    assert "'packages/secubox-pilotage/**'" in y and "'packages/secubox-pilotage-agent/**'" in y
