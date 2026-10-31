# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Task 10 (#3126) : le paquet secubox-pilotage — unité durcie, AppArmor, postinst, nginx, menu, agrégateur, CI."""
import os
import re
import subprocess
from pathlib import Path

import pytest

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
    # le SEUL emplacement d'écriture : données et journal d'audit (les sockets viennent de systemd, R26)
    rw = re.search(r"^ReadWritePaths=(.*)$", u, re.M).group(1).split()
    assert set(rw) == {"/var/lib/secubox/pilotage", "/var/log/secubox"}


def test_unite_sans_rm_ni_chgrp_ni_umask_de_socket():
    """R26 : les sockets sont créées par systemd ; plus de rm dans /run/secubox (collant), de chgrp en root ni de sleep."""
    u = code("systemd/secubox-pilotage.service")
    for interdit in ("ExecStartPre", "ExecStartPost", "chgrp", "rm -f", "0666", "/run/secubox"):
        assert interdit not in u, interdit
    assert "RestrictAddressFamilies=AF_UNIX" in u        # aucun port TCP
    assert "Requires=secubox-pilotage.socket secubox-pilotage-canal.socket" in u
    assert "Sockets=secubox-pilotage.socket secubox-pilotage-canal.socket" in u


def test_unites_socket():
    adm = lire("systemd/secubox-pilotage.socket")
    can = lire("systemd/secubox-pilotage-canal.socket")
    for texte, chemin, groupe, nom in ((adm, "/run/secubox/pilotage.sock", "secubox", "admin"),
                                       (can, "/run/secubox/pilotage-canal.sock", "www-data", "canal")):
        assert f"ListenStream={chemin}" in texte
        assert "SocketMode=0660" in texte and "SocketUser=secubox-pilotage" in texte and f"SocketGroup={groupe}" in texte
        assert f"FileDescriptorName={nom}" in texte and "Service=secubox-pilotage.service" in texte
        assert "RemoveOnStop=yes" in texte and "WantedBy=sockets.target" in texte
        assert "0666" not in texte
    assert "SocketGroup=www-data" not in adm and "SocketGroup=secubox" not in can    # le canal n'est jamais lisible par le groupe secubox


def test_profil_apparmor_enforce_et_borne():
    p = lire("apparmor/secubox-pilotage-api")
    assert p.rstrip().endswith("}") and "/usr/sbin/secubox-pilotage-api {" in p
    assert "complain" not in p
    assert "deny /etc/secubox/secrets/** r," in p
    assert "/var/lib/secubox/pilotage/** rwkm," in p
    assert "network inet" not in p                         # pas de réseau IP
    # R25 révisée au banc gk2 (#3126) : `a` seul refuse write() sur un descripteur O_APPEND ; `w` comme le reste du dépôt, et
    # l'ajout seul est tenu par le code (O_APPEND, jamais O_CREAT ni O_TRUNC : test_droits_reels_3126).
    assert re.search(r"^\s*/var/log/secubox/audit\.log w,$", p, re.M)
    # delegation.log : secubox_core/auth.py l'ouvre en "a" avec création, comme dans les autres modules -> w
    assert re.search(r"^\s*/var/log/secubox/delegation\.log w,$", p, re.M)
    assert not re.search(r"audit\.log\s+\S*[ra]\S*,", p)
    # M4 : pas de résolution de noms, et la seule pièce d'authentification lue sous auth/ est le registre des sessions
    assert "nameservice" not in p
    assert "/var/lib/secubox/auth/**" not in p and "/var/lib/secubox/auth/sessions.json r," in p
    # R26 : les sockets arrivent par descripteur (systemd), le profil n'a pas à les créer
    assert "pilotage.sock" not in p and "pilotage-canal.sock" not in p


def test_ecoute_et_declencheurs():
    s = lire("systemd/secubox-pilotage-ecoute.service")
    assert "Type=oneshot" in s and "ExecStart=/usr/sbin/secubox-pilotage-ecoute" in s
    chemin = lire("systemd/secubox-pilotage-ecoute.path")
    assert "PathChanged=/var/lib/secubox/p2p/wg_mesh.json" in chemin and "Unit=secubox-pilotage-ecoute.service" in chemin
    assert "PathChanged=/var/lib/secubox/autoload-public/pairs-publics.json" in chemin
    assert "OnUnitInactiveSec=" in lire("systemd/secubox-pilotage-ecoute.timer")


def test_unite_ecoute_durcie_et_acl_reposee_meme_en_echec():
    """I7 : socle § 10 (sauf User=, root requis) ; M8 : l'ACL du journal est reposée par ExecStopPost, qui tourne aussi quand ExecStart échoue."""
    s = code("systemd/secubox-pilotage-ecoute.service")
    for ligne in ("NoNewPrivileges=yes", "ProtectSystem=strict", "ProtectHome=yes", "PrivateTmp=yes", "PrivateDevices=yes",
                  "ProtectKernelTunables=yes", "ProtectKernelModules=yes", "ProtectKernelLogs=yes", "ProtectControlGroups=yes",
                  "RestrictSUIDSGID=yes", "RestrictNamespaces=yes", "RestrictRealtime=yes", "LockPersonality=yes", "UMask=0027",
                  "SystemCallArchitectures=native", "RestrictAddressFamilies=AF_UNIX AF_NETLINK"):
        assert ligne in s, ligne
    cap = re.search(r"^CapabilityBoundingSet=(.*)$", s, re.M).group(1).split()
    assert set(cap) <= {"CAP_NET_ADMIN", "CAP_DAC_OVERRIDE", "CAP_DAC_READ_SEARCH", "CAP_FOWNER"} and "CAP_NET_ADMIN" in cap
    rw = set(re.search(r"^ReadWritePaths=(.*)$", s, re.M).group(1).split())
    assert {"/etc", "/var/log/secubox"} <= rw and "/" not in rw
    assert "ExecStopPost=-/usr/sbin/secubox-pilotage-audit-acl" in s
    assert "setfacl" not in s                               # l'ACL passe par l'assistant, qui vérifie le fichier


def test_exception_rules_code_ecrite():
    """I7 : l'unité root de l'écouteur et la socket du canal en groupe www-data figurent dans les Exceptions de RULES-CODE."""
    regles = lire(".claude/RULES-CODE.md", DEPOT)
    lignes = [x for x in regles.splitlines() if "secubox-pilotage-ecoute.service" in x]
    assert len(lignes) == 1 and "secubox-pilotage-canal.socket" in lignes[0] and "www-data" in lignes[0]
    assert "systemd-run" in lignes[0] and "nginx -t" in lignes[0] and "AppArmor" in lignes[0] and "netmodes" in lignes[0]   # R30
    assert "packages/secubox-pilotage/tests/test_paquet.py::test_unite_ecoute_durcie_et_acl_reposee_meme_en_echec" in lignes[0]


def test_sysctl_nonlocal_bind_propre_au_paquet():
    """I2/R24 : listen 10.x.0.1:8472 exige ip_nonlocal_bind ; le paquet le livre lui-même (annuaire n'est qu'un Recommends)."""
    c = code("sysctl/31-secubox-pilotage-nonlocal-bind.conf")
    assert c.strip() == "net.ipv4.ip_nonlocal_bind = 1"
    r = code("debian/rules")
    assert "sysctl/31-secubox-pilotage-nonlocal-bind.conf" in r and "etc/sysctl.d" in r
    assert "sysctl -p /etc/sysctl.d/31-secubox-pilotage-nonlocal-bind.conf" in code("debian/postinst")


def test_nginx_administration_derriere_le_chemin_normal():
    c = lire("nginx/pilotage.conf")
    assert "location /api/v1/pilotage/" in c
    assert "proxy_pass http://unix:/run/secubox/pilotage.sock;" in c
    assert "pilotage-canal" not in c and "8472" not in c            # l'administration n'est jamais sur une IP de tunnel


def test_modele_du_canal_pose_x_real_ip():
    t = lire("nginx/pilotage-canal.conf.tpl")
    assert "proxy_set_header X-Real-IP $realip_remote_addr;" in t     # C1 : voir test_canal_nginx.py
    assert "proxy_set_header X-Forwarded-For $realip_remote_addr;" in t
    assert "include /etc/nginx/snippets/secubox-proxy.conf" not in t   # un seul auteur de X-Real-IP
    assert "client_max_body_size 256k;" in t and "proxy_read_timeout 60s;" in t


def test_controle_debian():
    c = lire("debian/control")
    assert "Package: secubox-pilotage\n" in c and "Architecture: all" in c and "Standards-Version: 4.6.2" in c
    assert lire("debian/compat").strip() == "13"
    ch = lire("debian/changelog").splitlines()[0]
    assert ch.startswith("secubox-pilotage (0.6.13-1~trixie1) trixie;")
    assert "Recommends: apparmor, secubox-p2p (>= 1.20.2~)" in c          # banc gk2 : projection p2p-public des pairs enrôlés
    depends = re.search(r"^Depends:(.*)$", c, re.M).group(1)
    assert "sudo" not in depends                                          # Final : plus aucune règle sudoers


@pytest.mark.parametrize("paquet", ["secubox-pilotage", "secubox-pilotage-agent", "secubox-p2p", "secubox-profiles",
                                    "secubox-annuaire"])
def test_changelogs_jamais_dates_dans_le_futur(paquet):
    """Final : une entrée porte la date réelle de sa livraison, jamais une date à venir (#3302 : généralisé, la règle d'origine
    visait le seul lendemain de la branche L5)."""
    from email.utils import parsedate_to_datetime
    from datetime import datetime, timezone
    dates = [parsedate_to_datetime(m) for m in re.findall(r"^ -- .*?>  (.+)$", lire(f"packages/{paquet}/debian/changelog", DEPOT), re.M)]
    assert dates and all(d <= datetime.now(timezone.utc) for d in dates)


def test_postinst_et_prerm():
    p = code("debian/postinst")
    assert "systemctl enable --now secubox-pilotage.service" in p
    assert "adduser --system" in p and "secubox-pilotage" in p
    assert "tmpfiles" not in p                                      # systemd-tmpfiles refuse ces chemins
    # I3 : le dossier de données est préparé par descripteur (python3 -I), pas par chemin shell
    assert "python3 -I /usr/lib/secubox/pilotage/init_donnees.py" in p
    assert "rm -f /var/lib/secubox/pilotage" not in p and "install -d -o secubox-pilotage" not in p
    # I4 : l'ACL du journal passe par l'assistant qui vérifie le fichier ; ni setfacl direct ni chmod/chown du journal
    assert "/usr/sbin/secubox-pilotage-audit-acl" in p and "setfacl" not in p
    assert not [x for x in p.splitlines() if "audit.log" in x and ("chmod" in x or "chown" in x or "chgrp" in x)]
    assert "apparmor_parser -r /etc/apparmor.d/secubox-pilotage-api" in p
    assert "/usr/sbin/secubox-pilotage-ecoute" in p
    assert "/etc/secubox/pilotage" not in p                         # M8 : dossier jamais utilisé par le maître
    assert "systemctl enable --now secubox-pilotage.socket secubox-pilotage-canal.socket" in p
    prerm = code("debian/prerm")
    assert "systemctl stop secubox-pilotage.service" in prerm
    assert "secubox-pilotage-ecoute --retirer" in prerm             # R28 : règles nft retirées
    for sh in ("debian/postinst", "debian/prerm", "debian/postrm", "sbin/secubox-pilotage-ecoute"):
        assert subprocess.run(["sh" if "ecoute" not in sh else "bash", "-n", str(ICI / sh)]).returncode == 0, sh


def test_pas_d_entree_de_menu_et_hors_arbre():
    """R29 : 595-fleet (annuaire) existe ; les deux paquets sont installés à la demande, hors de l'arbre des méta-paquets."""
    assert not (ICI / "menu.d").exists()
    assert "menu.d" not in lire("debian/rules")
    arbre = lire("secubox-meta/arbre.yaml", DEPOT / "packages")
    hors = arbre[arbre.index("\nhors-arbre:"):]
    for nom in ("secubox-pilotage", "secubox-pilotage-agent"):
        assert re.search(rf"^  - {nom}\s+#.*#3126", hors, re.M), nom


def test_spdx_partout():
    """M6 : les fichiers SUIVIS par git (pas les caches ni les artefacts de build du poste)."""
    suivis = subprocess.run(["git", "ls-files", "."], cwd=ICI, capture_output=True, text=True, check=True).stdout.split()
    assert suivis
    for rel in suivis:
        chemin = ICI / rel
        if not chemin.exists() or chemin.suffix in (".pyc", ".json") or chemin.name in ("compat", "control", "changelog", "format"):
            continue
        assert "LicenseRef-CMSD-1.0" in chemin.read_text(encoding="utf-8")[:600], chemin
        assert chemin.name == "test_paquet.py" or "SA" + "SU" not in chemin.read_text(encoding="utf-8"), chemin


def test_aucun_artefact_de_build_dans_le_paquet():
    for motif in ("debian/files", "debian/.debhelper", "debian/secubox-pilotage", "debian/*.substvars", "debian/*.debhelper.log"):
        assert not list(ICI.glob(motif)), motif
    assert not list(ICI.parent.glob("secubox-pilotage_*"))


def test_pilotage_dans_dedicated_modules():
    main = lire("secubox-aggregator/aggregator/main.py", DEPOT / "packages")
    ligne = re.search(r"DEDICATED_MODULES = frozenset\(\{(.*?)\}\)", main, re.S).group(1)
    assert '"pilotage"' in ligne
    migrate = lire("secubox-aggregator/sbin/secubox-aggregator-migrate", DEPOT / "packages")
    assert "pilotage" in re.search(r'readonly AGG_EXCLUDE="([^"]*)"', migrate).group(1).split()


def test_pilotage_dans_la_matrice_ci():
    y = lire(".github/workflows/backend-tests.yml", DEPOT)
    assert re.search(r"- suite: secubox-pilotage\n\s+chemin: packages/secubox-pilotage/tests", y)
    assert re.search(r"- suite: secubox-pilotage-agent\n\s+module: packages/secubox-pilotage-agent\n\s+cache: 'false'", y)   # pas de go.sum
    assert "cache: ${{ matrix.cache != 'false' }}" in y
    assert "'packages/secubox-pilotage/**'" in y and "'packages/secubox-pilotage-agent/**'" in y


def test_unite_ecoute_commentaire_juste():
    s = lire("systemd/secubox-pilotage-ecoute.service")
    assert "nginx -t ne lie rien" not in s
    assert "systemd-run" in s            # le commentaire dit où tourne nginx -t


def test_plan_compte_de_l_agent():
    plan = lire("docs/superpowers/plans/2026-10-28-pilotage-l1-voir.md", DEPOT)
    assert "utilisateur dédié `secubox-pilotage` (jamais root)" not in plan
    assert "utilisateur dédié `secubox-pilotage-agent` (jamais root)" in plan


def test_la_doc_du_marqueur_dit_ce_qu_il_protege_et_ce_qu_il_ne_protege_pas():
    """Relecture de la tâche 0 (L2), Minor 1 : le marqueur arrête un RELAIS qui transmet les en-têtes du client (agrégateur, autre entrée
    nginx), PAS un processus qui joint directement la socket : celui-là forge aussi le marqueur. Contre lui, la barrière est la socket
    (0660, groupe www-data). Aucun texte ne doit promettre le contraire."""
    import api.canal as canal
    # l'entrée qui documente le marqueur (0.2.2), pas forcément la plus récente
    entree = next(e for e in lire("debian/changelog").split("\n -- ") if "HTTP_INCONNUS_PAR_MINUTE" in e)
    for texte in (canal.__doc__, entree, lire("README.md")):
        assert "processus local du groupe www-data) ne choisit pas" not in texte
        assert "processus local qui joindrait la socket ne choisit plus" not in texte
        assert "ne protège pas" in texte and "0660" in texte and "relais" in texte


# --- L2 tâche 6 (R-L2-35) : assistant d'émission du code de jonction ---

def test_assistant_invite_active_par_socket_au_seul_service():
    s = lire("systemd/secubox-pilotage-invite.socket")
    for ligne in ("ListenStream=/run/secubox-pilotage/invite.sock", "Accept=yes", "SocketUser=secubox-pilotage",
                  "SocketGroup=secubox-pilotage", "SocketMode=0600", "DirectoryMode=0755", "RemoveOnStop=yes", "WantedBy=sockets.target"):
        assert ligne in s, ligne
    assert re.search(r"^MaxConnections=[1-4]$", s, re.M)


def test_assistant_invite_unite_sous_le_compte_des_jetons_et_durcie():
    u = code("systemd/secubox-pilotage-invite@.service")
    for ligne in ("User=secubox", "Group=secubox", "ExecStart=/usr/sbin/secubox-pilotage-invite", "StandardInput=socket",
                  "StandardOutput=socket", "StandardError=journal", "NoNewPrivileges=yes", "ProtectSystem=strict", "ProtectHome=yes",
                  "PrivateTmp=yes", "PrivateDevices=yes", "ProtectKernelTunables=yes", "ProtectControlGroups=yes", "RestrictSUIDSGID=yes",
                  "LockPersonality=yes", "UMask=0027", "CapabilityBoundingSet=", "RestrictAddressFamilies=AF_UNIX AF_NETLINK",
                  "IPAddressDeny=any"):
        assert re.search(rf"^{re.escape(ligne)}$", u, re.M), ligne
    assert re.search(r"^RuntimeMaxSec=\d+$", u, re.M)
    rw = [x for ligne in u.splitlines() if ligne.startswith("ReadWritePaths=") for x in ligne.split("=", 1)[1].split()]
    assert set(rw) == {"-/var/lib/secubox/p2p/master-link", "/var/log/secubox"}     # M5 : absent (p2p non installé) = pas d'échec
    assert "sudo" not in u
    assert re.search(r"^AppArmorProfile=secubox-pilotage-invite$", u, re.M)


def test_assistant_invite_installe_active_et_arrete():
    r = lire("debian/rules")
    assert "sbin/secubox-pilotage-invite" in r and "secubox-pilotage-invite.socket" in r and "secubox-pilotage-invite@.service" in r
    assert "enable --now secubox-pilotage-invite.socket" in code("debian/postinst")
    assert "secubox-pilotage-invite.socket" in code("debian/prerm")
    assert "secubox-p2p" in lire("debian/control")


def test_profil_api_joint_la_socket_de_l_assistant_seulement():
    p = code("apparmor/secubox-pilotage-api")
    assert "/run/secubox-pilotage/invite.sock rw," in p
    assert "sbx-mesh-invite" not in p and "/usr/bin/sudo" not in p   # le service n'exécute rien


def test_service_maitre_toujours_sans_sudo_ni_reseau_ip():
    u = code("systemd/secubox-pilotage.service")
    assert "NoNewPrivileges=yes" in u and "RestrictAddressFamilies=AF_UNIX" in u and "sudo" not in u


def test_assistant_invite_profil_apparmor_enforce():
    """I2 (R-L2-39) : pas d'exception, un profil enforce comme pour chaque service (AGENTS.md)."""
    p = lire("apparmor/secubox-pilotage-invite")
    c = code("apparmor/secubox-pilotage-invite")
    assert "profile secubox-pilotage-invite /usr/sbin/secubox-pilotage-invite" in c and "complain" not in c
    for regle in ("/usr/sbin/secubox-pilotage-invite r,", "/usr/bin/python3* rix,", "/usr/bin/sbx-mesh-invite rix,",
                  "/usr/lib/secubox/p2p/** r,", "/var/lib/secubox/p2p/master-link/ r,", "/var/lib/secubox/p2p/master-link/** rwk,",
                  "/var/log/secubox/audit.log w,", "/{,usr/}{,s}bin/ip rix,", "network netlink raw,", "deny /etc/secubox/secrets/** r,"):
        assert regle in c, regle
    for interdit in ("/bin/sh", "/bin/bash", "/usr/bin/sudo", "/bin/dash", "capability", "network inet", " ux,", " Ux,", " px,", " Px,"):
        assert interdit not in c, interdit
    assert p.rstrip().endswith("}")
    r = lire("debian/rules")
    assert "apparmor/secubox-pilotage-invite $(P)/etc/apparmor.d/secubox-pilotage-invite" in r
    assert "apparmor_parser -r /etc/apparmor.d/secubox-pilotage-invite" in code("debian/postinst")



def test_exception_reduite_au_compte_partage():
    """R-L2-40 : seule exception, le compte partagé `secubox` (propriétaire de tokens.json et master-link de secubox-p2p)."""
    lignes = [x for x in lire(".claude/RULES-CODE.md", DEPOT).splitlines() if "secubox-pilotage-invite@.service" in x]
    assert len(lignes) == 1
    for mot in ("User=secubox", "#3126", "tokens.json", "master-link", "enforce", "0600", "argv fixe",
                "packages/secubox-pilotage/tests/test_paquet.py::test_exception_reduite_au_compte_partage"):
        assert mot in lignes[0], mot


def test_profils_apparmor_se_compilent():
    import shutil
    if shutil.which("apparmor_parser") is None:
        import pytest
        pytest.skip("apparmor_parser absent")
    for nom in ("secubox-pilotage-api", "secubox-pilotage-invite"):
        r = subprocess.run(["apparmor_parser", "-Q", "-K", str(ICI / "apparmor" / nom)], capture_output=True, text=True)
        assert r.returncode == 0, r.stderr


def _postrm(tmp_path, action, lien=False):
    """postrm avec setfacl, apparmor_parser, nginx et systemctl simulés (journal des appels), chemins redirigés sous tmp_path."""
    bin_ = tmp_path / "bin"
    bin_.mkdir()
    for nom, rc in (("setfacl", 1), ("apparmor_parser", 1), ("nginx", 1), ("systemctl", 1)):
        (bin_ / nom).write_text(f'#!/bin/sh\necho "{nom} $*" >> "{tmp_path}/appels"\nexit {rc}\n')
        (bin_ / nom).chmod(0o755)
    journaux, aa, aa_sys = tmp_path / "log", tmp_path / "apparmor.d", tmp_path / "sys-apparmor"
    for d in (journaux, aa, aa_sys):
        d.mkdir()
    (journaux / "audit.log.1").write_text("ancienne\n")
    if lien:
        (tmp_path / "cible").write_text("")
        (journaux / "audit.log").symlink_to(tmp_path / "cible")
    else:
        (journaux / "audit.log").write_text("ligne\n")
    env = dict(os.environ, PATH=f"{bin_}{os.pathsep}{os.environ['PATH']}", SECUBOX_PILOTAGE_JOURNAUX=str(journaux),
               SECUBOX_PILOTAGE_APPARMOR_D=str(aa), SECUBOX_PILOTAGE_APPARMOR_SYS=str(aa_sys),
               SECUBOX_PILOTAGE_CANAL_CONF=str(tmp_path / "canal.conf"))
    r = subprocess.run(["sh", str(ICI / "debian" / "postrm"), action], env=env, capture_output=True, text=True, timeout=30)
    appels = (tmp_path / "appels").read_text().splitlines() if (tmp_path / "appels").exists() else []
    return r, appels, journaux, aa


@pytest.mark.parametrize("action", ["remove", "purge"])
def test_postrm_retire_l_acl_et_decharge_les_profils_m12(tmp_path, action):
    r, appels, journaux, aa = _postrm(tmp_path, action)
    assert r.returncode == 0, r.stderr                         # outils en échec : jamais d'échec du postrm
    assert f"setfacl -P -x u:secubox-pilotage {journaux}/audit.log" in appels
    assert f"setfacl -P -x u:secubox-pilotage {journaux}/audit.log.1" in appels   # journal tourné : même inode, même ACL
    for profil in ("secubox-pilotage-api", "secubox-pilotage-invite"):
        assert f"apparmor_parser -R {aa}/{profil}" in appels


@pytest.mark.parametrize("action", ["upgrade", "failed-upgrade", "abort-install", "abort-upgrade", "disappear"])
def test_postrm_hors_remove_et_purge_ne_touche_a_rien_m12(tmp_path, action):
    r, appels, _, _ = _postrm(tmp_path, action)
    assert r.returncode == 0, r.stderr
    assert not [a for a in appels if a.startswith(("setfacl", "apparmor_parser"))], appels


def test_postrm_ne_suit_jamais_un_lien_a_la_place_du_journal_m12(tmp_path):
    r, appels, journaux, _ = _postrm(tmp_path, "purge", lien=True)
    assert r.returncode == 0, r.stderr
    assert not [a for a in appels if a.endswith(f"{journaux}/audit.log")], appels


def test_unite_vhost_root_bornee_et_exception_ecrite():
    """Final I2 : le ctl root des vhosts figure dans les Exceptions de RULES-CODE ; capacités bornées, écritures limitées aux
    fichiers et dossiers réellement écrits (jamais tout /etc/secubox)."""
    u = lire("systemd/secubox-pilotage-vhost.service")
    caps = re.search(r"^CapabilityBoundingSet=(.*)$", u, re.M).group(1).split()
    # CAP_NET_ADMIN (#3302, banc gk4) : `secubox-relais-maillage pair-de` lit `wg show wg-mesh` pour vérifier la reprise d'admin.<box>
    assert sorted(caps) == ["CAP_CHOWN", "CAP_DAC_OVERRIDE", "CAP_DAC_READ_SEARCH", "CAP_FOWNER", "CAP_NET_ADMIN"]
    assert re.search(r"^AmbientCapabilities=$", u, re.M)
    rw = [d.lstrip("-") for li in u.splitlines() if li.startswith("ReadWritePaths=") for d in li.split("=", 1)[1].split()]
    assert "/etc/secubox" not in rw and "/etc" not in rw
    assert {"/etc/secubox/haproxy.toml", "/etc/secubox/waf", "/etc/nginx/conf.d", "/var/lib/secubox-pilotage-pages",
            "/var/log/secubox", "/data/haproxy", "/etc/letsencrypt"} <= set(rw)
    regles = lire(".claude/RULES-CODE.md", DEPOT)
    lignes = [x for x in regles.splitlines() if "secubox-pilotage-vhost.service" in x]
    assert len(lignes) == 1
    for mot in ("haproxyctl", "secubox-waf-route", "certbot", "nginx", "systemd-run", "CAP_CHOWN",
                "packages/secubox-pilotage/tests/test_paquet.py::test_unite_vhost_root_bornee_et_exception_ecrite"):
        assert mot in lignes[0], mot
