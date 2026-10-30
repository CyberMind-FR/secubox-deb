# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3126 L1 : contrôles statiques du paquet secubox-pilotage-agent (unité, règles, go.mod, AppArmor)."""
import re
import shutil
import subprocess
from pathlib import Path

RACINE = Path(__file__).resolve().parents[1]


def lire(rel):
    return (RACINE / rel).read_text(encoding="utf-8")


def sans_commentaires(txt):
    return "\n".join(ligne for ligne in txt.splitlines() if not ligne.lstrip().startswith("#"))


# Options qui posent un filtre seccomp : sous User= non root, systemd impose alors NoNewPrivileges et sudo répond
# « no new privileges flag is set » (précédents netmodes, autoload, voicestudio).
SECCOMP = ("ProtectKernelTunables", "LockPersonality", "RestrictSUIDSGID", "SystemCallFilter", "SystemCallArchitectures",
           "RestrictNamespaces", "RestrictAddressFamilies", "MemoryDenyWriteExecute", "PrivateDevices",
           "ProtectKernelModules", "ProtectKernelLogs", "ProtectClock", "ProtectHostname", "RestrictRealtime",
           "RestrictFileSystems", "DynamicUser")


def cles(u):
    return {ligne.split("=", 1)[0].strip() for ligne in u.splitlines() if "=" in ligne}


def test_unite_durcie():
    u = sans_commentaires(lire("systemd/secubox-pilotage-agent.service"))
    for d in (
        "User=secubox-pilotage-agent", "Group=secubox-pilotage-agent", "ProtectSystem=strict", "ProtectHome=yes",
        "PrivateTmp=yes", "IPAddressDeny=any", "IPAddressAllow=10.10.0.1 10.64.0.1 localhost",
        "MemoryMax=48M", "Restart=on-failure", "RestartSec=10", "ReadOnlyPaths=/", "ProtectControlGroups=yes",
        "ExecStart=/usr/sbin/sbx-pilotage-agent",
    ):
        assert d in u, d
    assert "Listen" not in u
    assert "User=root" not in u
    assert re.search(r"^AmbientCapabilities=\s*$", u, re.M)  # l'agent lui-même n'a aucune capacité


def test_unite_permet_sudo_vers_le_ctl_seulement():
    """L2 (R-L2-3) : NoNewPrivileges=no, SEULEMENT pour `sudo -n secubox-pilotagectl` ; rien qui l'impose par seccomp ;
    le ctl root hérite de l'espace de montage de l'unité : ses dossiers d'écriture y sont ouverts, et eux seuls."""
    u = sans_commentaires(lire("systemd/secubox-pilotage-agent.service"))
    assert "NoNewPrivileges=no" in u and "NoNewPrivileges=yes" not in u
    for cle in SECCOMP:
        assert cle not in cles(u), cle
    cap = re.search(r"^CapabilityBoundingSet=(.*)$", u, re.M).group(1).split()
    # sudo (setuid, setgroups, journal d'audit noyau) ; le ctl écrit audit.log (secubox, 0640) et lit modules.d
    # CAP_CHOWN (M3) : le ctl crée audit.log au compte secubox sur une box neuve
    # CAP_NET_ADMIN (tâche 2) : `wg show <interface> allowed-ips` (ancre-verifier) l'exige du noyau, même pour root
    assert set(cap) == {"CAP_SETUID", "CAP_SETGID", "CAP_AUDIT_WRITE", "CAP_DAC_OVERRIDE", "CAP_DAC_READ_SEARCH",
                        "CAP_CHOWN", "CAP_NET_ADMIN"}
    rw = re.search(r"^ReadWritePaths=(.*)$", u, re.M).group(1).split()
    assert set(rw) == {"/var/log/secubox", "-/var/lib/secubox-pilotagectl"}
    brut = lire("systemd/secubox-pilotage-agent.service")
    assert "seulement pour sudo" in brut and "secubox-pilotagectl" in brut


def test_unite_couvre_chaque_ecriture_du_ctl():
    """Croisé avec le ctl : l'état root et le journal d'audit, seuls endroits écrits sous sudo depuis l'agent
    (/etc/secubox/pilotage n'est écrit que par `mains-liees`, local seulement, hors de l'unité)."""
    ctl = lire("sbin/secubox-pilotagectl")
    assert 'self.etat = f"{self.r}/var/lib/secubox-pilotagectl"' in ctl
    assert 'self.journaux = f"{self.r}/var/log/secubox"' in ctl


def test_sudoers_argv_borne_au_ctl():
    s = lire("sudoers.d/secubox-pilotage-agent")
    regles = [ligne for ligne in sans_commentaires(s).splitlines() if ligne.strip()]
    assert regles == ["secubox-pilotage-agent ALL=(root) NOPASSWD: /usr/sbin/secubox-pilotagectl *"]
    visudo = shutil.which("visudo") or ("/usr/sbin/visudo" if Path("/usr/sbin/visudo").exists() else None)
    if visudo:
        p = subprocess.run([visudo, "-cf", str(RACINE / "sudoers.d/secubox-pilotage-agent")],
                           capture_output=True, text=True)
        assert p.returncode == 0, p.stdout + p.stderr


def test_ctl_python_isole_et_executable():
    for nom in ("secubox-pilotagectl", "secubox-pilotage"):
        ctl = RACINE / "sbin" / nom
        assert ctl.read_text().startswith("#!/usr/bin/python3 -I\n"), nom  # ni PYTHON*, ni dossier courant, ni site
        assert ctl.stat().st_mode & 0o111, nom


def test_regles_installent_la_commande_locale():
    """Tâche 4 : commande du détenteur, 0755 (un compte non root reçoit son message « à lancer en root » ; le ctl
    refuse de toute façon hors root), jamais dans le sudoers de l'agent."""
    assert "install -D -m 0755 sbin/secubox-pilotage $(P)/usr/sbin/secubox-pilotage" in lire("debian/rules")
    assert "secubox-pilotage " not in sans_commentaires(lire("sudoers.d/secubox-pilotage-agent")).replace(
        "secubox-pilotage-agent ", "")


def test_regles_installent_ctl_sudoers_et_tmpfiles():
    r = lire("debian/rules")
    assert "install -D -m 0755 sbin/secubox-pilotagectl $(P)/usr/sbin/secubox-pilotagectl" in r
    assert "install -D -m 0440 sudoers.d/secubox-pilotage-agent $(P)/etc/sudoers.d/secubox-pilotage-agent" in r
    assert ("install -D -m 0644 tmpfiles.d/secubox-pilotagectl.conf $(P)/usr/lib/tmpfiles.d/secubox-pilotagectl.conf"
            in r)
    t = [ligne for ligne in sans_commentaires(lire("tmpfiles.d/secubox-pilotagectl.conf")).splitlines() if ligne.strip()]
    assert t == ["d /var/lib/secubox-pilotagectl 0700 root root -"]
    pi = sans_commentaires(lire("debian/postinst"))
    assert "systemd-tmpfiles --create /usr/lib/tmpfiles.d/secubox-pilotagectl.conf" in pi
    assert pi.index("systemd-tmpfiles --create") < pi.index("systemctl enable --now")
    c = lire("debian/control")
    assert re.search(r"^Depends:.*\bsudo\b", c, re.M) and re.search(r"^Depends:.*\bpython3 \(>= 3\.11\)", c, re.M)
    assert "rm -rf /var/lib/secubox-pilotagectl" in lire("debian/postrm")


def test_exception_ecrite_dans_rules_code():
    regles = (RACINE.parents[1] / ".claude/RULES-CODE.md").read_text(encoding="utf-8")
    lignes = [ligne for ligne in regles.splitlines()
              if ligne.startswith("| § 10 durcissement | `secubox-pilotage-agent.service`")]
    assert len(lignes) == 1
    for mot in ("NoNewPrivileges=no", "secubox-pilotagectl", "ReadWritePaths", "AppArmor",
                "tests/test_paquet_agent.py::test_unite_permet_sudo_vers_le_ctl_seulement"):
        assert mot in lignes[0], mot


def test_regles_construisent_sans_cgo():
    r = lire("debian/rules")
    assert re.search(r"^export CGO_ENABLED\s*=\s*0", r, re.M)
    assert "-trimpath" in r
    assert "DEB_HOST_ARCH" in r and "GOARCH" in r
    assert "./cmd/sbx-pilotage-agent" in r


def test_aucune_dependance_go_tierce():
    mod = lire("go.mod")
    assert "require" not in mod
    assert re.search(r"^go 1\.22", mod, re.M)
    assert not (RACINE / "vendor").exists() and not (RACINE / "go.sum").exists()


def test_apparmor_enforce_sans_reseau_entrant():
    p = lire("apparmor/usr.sbin.sbx-pilotage-agent")
    code = sans_commentaires(p)
    assert re.search(r"^/usr/sbin/sbx-pilotage-agent\s*\{", code, re.M)
    assert "complain" not in code and "flags=" not in code  # enforce
    assert not re.search(r"\blisten\b|\baccept\b", code)
    # chaque règle inet est qualifiée (jamais « network inet stream, » nu, qui autoriserait listen)
    inet = [ligne for ligne in code.splitlines() if ligne.strip().startswith("network") and "inet" in ligne]
    assert inet and all("(" in ligne and "connect" in ligne for ligne in inet)
    assert "deny /etc/secubox/secrets/** r" in code
    assert "/usr/bin/systemctl rix," in code
    assert "capability" not in code
    # L2 : le seul passage privilégié, sudo, hors du profil (Ux) ; ce qu'il permet est borné par le sudoers et le ctl
    assert "/usr/bin/sudo Ux," in code
    execs = [ligne.strip() for ligne in code.splitlines() if re.search(r"\s[a-zA-Z]*[uUpPcCi]x,\s*$", ligne)]
    assert execs == ["/usr/bin/systemctl rix,", "/usr/bin/sudo Ux,"], execs


def test_paquet_coherent():
    c = lire("debian/control")
    assert "Architecture: any" in c and "Standards-Version: 4.6.2" in c
    assert lire("debian/compat").strip() == "13"
    assert lire("debian/changelog").startswith("secubox-pilotage-agent (0.5.1-1~trixie1) trixie;")
    # ancre-verifier lit `wg show` par chemin absolu (/usr/bin/wg)
    assert "wireguard-tools" in re.search(r"^Depends:(.*)$", c, re.M).group(1)
    pi = lire("debian/postinst")
    for m in ("adduser --system --no-create-home --group secubox-pilotage-agent",
              "apparmor_parser", "systemctl enable --now secubox-pilotage-agent"):
        assert m in pi, m
    assert "systemctl stop secubox-pilotage-agent" in lire("debian/prerm")


def test_entetes_spdx():
    fichiers = ["debian/rules", "debian/postinst", "debian/prerm", "debian/postrm", "README.md",
                "systemd/secubox-pilotage-agent.service", "apparmor/usr.sbin.sbx-pilotage-agent",
                "conf/pilotage-agent.env", "tests/test_paquet_agent.py", "tests/test_pilotagectl.py",
                "tests/test_pilotage_local.py", "sbin/secubox-pilotage", "sbin/secubox-pilotagectl", "sudoers.d/secubox-pilotage-agent", "tmpfiles.d/secubox-pilotagectl.conf"]
    fichiers += [str(f.relative_to(RACINE)) for f in (RACINE / "cmd").rglob("*.go")]
    for rel in fichiers:
        assert "LicenseRef-CMSD-1.0" in lire(rel), rel


def test_apparmor_modele_de_carte_par_le_chemin_resolu():
    # /proc/device-tree est un lien : AppArmor contrôle /sys/firmware/devicetree/base/model
    code = sans_commentaires(lire("apparmor/usr.sbin.sbx-pilotage-agent"))
    assert "/sys/firmware/devicetree/base/model r," in code
    assert "/sys/class/dmi/id" not in code


def test_apparmor_dbus_restreint_a_systemd():
    code = sans_commentaires(lire("apparmor/usr.sbin.sbx-pilotage-agent"))
    assert not re.search(r"^\s*dbus\s*(\([^)]*\))?\s*bus=system\s*,", code, re.M)  # jamais de dbus nu
    assert "peer=(name=org.freedesktop.systemd1)" in code
    assert "peer=(name=org.freedesktop.DBus)" in code
    assert "ListUnitsByPatterns" in code
    assert "/run/systemd/private" not in code
    assert "/sys/fs/cgroup/ r," in code


def test_apparmor_resserre():
    code = sans_commentaires(lire("apparmor/usr.sbin.sbx-pilotage-agent"))
    assert "deny @{PROC}/[0-9]*/{cmdline,environ} r," in code
    assert re.search(r"^\s*network \([^)]*\) unix stream,", code, re.M)
    assert not re.search(r"^\s*network unix stream,", code, re.M)
    assert "/sys/devices/** r," not in code


def test_unite_confinee_et_ordonnee():
    u = sans_commentaires(lire("systemd/secubox-pilotage-agent.service"))
    for d in ("AppArmorProfile=/usr/sbin/sbx-pilotage-agent", "UMask=0027",
              "Wants=network-online.target"):
        assert d in u, d
    after = re.search(r"^After=(.*)$", u, re.M).group(1).split()
    assert {"network-online.target", "wg-quick@wg-mesh.service", "wg-quick@wg-autoload.service"} <= set(after)


def test_postinst_postrm_robustes():
    assert "[ -d /run/systemd/system ]" in lire("debian/postinst")
    assert "apparmor_parser -R" in lire("debian/postrm")


def test_regles_goarch_complet():
    r = lire("debian/rules")
    assert "armhf" in r and "386" in r and "GOARM" in r


def test_apparmor_dmi_x86_par_le_chemin_resolu():
    # /sys/class/dmi/id est un lien vers /sys/devices/virtual/dmi/id/
    code = sans_commentaires(lire("apparmor/usr.sbin.sbx-pilotage-agent"))
    assert "/sys/devices/virtual/dmi/id/{product_name,sys_vendor} r," in code


def test_compte_propre_distinct_du_maitre():
    """R27 : le maître (secubox-pilotage) et l'agent coexistent sur gk2 : deux comptes, jamais partagés."""
    u = sans_commentaires(lire("systemd/secubox-pilotage-agent.service"))
    assert "User=secubox-pilotage\n" not in u + "\n" and "Group=secubox-pilotage\n" not in u + "\n"
    p = sans_commentaires(lire("debian/postinst"))
    assert "getent passwd secubox-pilotage-agent" in p and "getent passwd secubox-pilotage >" not in p


def test_postinst_ne_touche_rien_sous_etc_secubox():
    """I1/R36 : /etc/secubox appartient au compte partagé secubox ; un `install -d -m`, `chmod`, `chown` ou `mkdir` de root y suivrait un lien
    posé par ce compte (root rendrait lisible /etc/secubox/secrets). Le postinst ne crée ni ne modifie rien sous /etc/secubox."""
    code = sans_commentaires(lire("debian/postinst"))
    # L5 tâche 2 (R-L5-13, R-L5-18) : les SEULS arbres touchés sont ceux du relais, hors des arbres partagés —
    # /etc/secubox-pilotage (root:root 0755) et /var/lib/secubox-pilotage-relais (compte du relais, 0700).
    arbres_du_relais = ("/etc/secubox-pilotage", "/var/lib/secubox-pilotage-relais")
    for ligne in code.splitlines():
        assert not re.search(r"/etc/secubox(?!-pilotage\b)", ligne), ligne
        if re.search(r"\b(install\s+-d|mkdir|chmod|chown|mktemp|mv)\b", ligne):
            assert any(a in ligne for a in arbres_du_relais) or re.fullmatch(r'\s*(chown root:root|chmod 0644) "\$tmp"', ligne), ligne
    assert "mkdir" not in code


def test_reglages_lus_par_l_agent_jamais_par_systemd():
    """R36 : le fichier d'environnement est lu par l'agent lui-même (par descripteur, root:root, sans écriture groupe/autres, sans lien) :
    un EnvironmentFile= de systemd suivrait un lien déposé dans /etc/secubox."""
    u = sans_commentaires(lire("systemd/secubox-pilotage-agent.service"))
    assert "EnvironmentFile" not in u
    code = sans_commentaires(lire("apparmor/usr.sbin.sbx-pilotage-agent"))
    assert "/etc/secubox/pilotage-agent.env r," in code
    main = lire("cmd/sbx-pilotage-agent/main.go")
    assert 'chargerReglages("/", lecture.Root, os.Setenv)' in main


def _octets(valeur):
    n, unite = re.fullmatch(r"(\d+)(MiB|M|KiB|K)", valeur).groups()
    return int(n) << (20 if unite.startswith("M") else 10)


def test_gomemlimit_sous_memorymax_m13():
    """M13 : le runtime Go connaît sa borne (GOMEMLIMIT) et collecte AVANT le tueur du cgroup (MemoryMax)."""
    u = sans_commentaires(lire("systemd/secubox-pilotage-agent.service"))
    env = re.findall(r"^Environment=GOMEMLIMIT=(\S+)$", u, re.M)
    (maxi,) = re.findall(r"^MemoryMax=(\S+)$", u, re.M)
    assert env == ["32MiB"], env
    assert _octets(env[0]) < _octets(maxi) == 48 << 20


def test_l5_agent_joint_le_relais_seulement():
    """L5 tâche 3 : l'agent connecte la SEULE socket du relais (aucune autre sous /run/secubox) et lit le drapeau des
    mains liées dans l'arbre root /etc/secubox-pilotage (même vérification que le relais) ; l'unité démarre après
    la socket du relais ; mémoire relevée pour un échange de 4 Mio (trois copies base64 brèves)."""
    code = sans_commentaires(lire("apparmor/usr.sbin.sbx-pilotage-agent"))
    run = [ligne.strip() for ligne in code.splitlines() if "/run/secubox" in ligne and "/run/secubox/pilotage/" not in ligne]
    assert run == ["/run/secubox/pilotage-relais.sock rw,"], run  # T7 : la page d'état (/run/secubox/pilotage/), test dédié
    assert "/etc/secubox-pilotage/ r," in code and "/etc/secubox-pilotage/mains-liees r," in code
    # R-L5-21 : drapeaux d'échéance relus à chaque message, sans sudo
    assert "/etc/secubox-pilotage/proprietaire r," in code and "/etc/secubox-pilotage/support-ouvert r," in code
    pi = lire("debian/postinst")
    assert "/usr/sbin/secubox-pilotagectl etat >/dev/null" in pi       # reprojection de l'état root à chaque configure
    assert "/etc/secubox-pilotage/relais.pub" not in code and "/var/lib/secubox-pilotage-relais" not in code
    u = sans_commentaires(lire("systemd/secubox-pilotage-agent.service"))
    after = re.search(r"^After=(.*)$", u, re.M).group(1).split()
    assert "secubox-pilotage-relais.socket" in after
    assert "Requires=secubox-pilotage-relais.socket" not in u          # l'agent vit sans relais (L1/L2)
    assert "MemoryMax=48M" in u and "Environment=GOMEMLIMIT=32MiB" in u


def test_acl_en_dependance():
    """R-L5-20 M1 : setfacl (paquet acl) pose l'ACL d'audit du relais."""
    c = lire("debian/control")
    assert re.search(r"^Depends:.*\bacl\b", c, re.M)


def test_mesure_rss_alignee_sur_l_unite():
    """R-L5-22 M3 : le test de RSS de l'agent se mesure avec le GOMEMLIMIT de l'unité."""
    u = sans_commentaires(lire("systemd/secubox-pilotage-agent.service"))
    (env,) = re.findall(r"^Environment=GOMEMLIMIT=(\S+)$", u, re.M)
    assert f'const GOMEMLIMITUnite = "{env}"' in lire("internal/canal/memoire_test.go")


def test_l5_page_etat_seule_ecriture_de_l_agent():
    """L5 tâche 7 : la page d'état locale est la SEULE écriture de l'agent lui-même : son dossier vient de l'unité
    (RuntimeDirectory secubox/pilotage, 0755 : nginx la lit), le profil AppArmor n'ouvre que la page et son fichier de
    travail au nom fixe, rien d'autre sous /run/secubox."""
    u = sans_commentaires(lire("systemd/secubox-pilotage-agent.service"))
    assert re.search(r"^RuntimeDirectory=secubox/pilotage$", u, re.M)
    assert re.search(r"^RuntimeDirectoryMode=0755$", u, re.M)
    code = sans_commentaires(lire("apparmor/usr.sbin.sbx-pilotage-agent"))
    ecritures = re.findall(r"^\s*(/run/secubox/pilotage/\S*)\s+(\w+),", code, re.M)
    assert sorted(ecritures) == [("/run/secubox/pilotage/", "r"), ("/run/secubox/pilotage/.etat.html.tmp", "rw"),
                                 ("/run/secubox/pilotage/etat.html", "w")]
    assert "/run/secubox/pilotage/** " not in code and "/run/secubox/** " not in code
    go = lire("cmd/sbx-pilotage-agent/etat.go")
    assert 'cheminEtat = "/run/secubox/pilotage/etat.html"' in go
    assert 'temporaire = ".etat.html.tmp"' in lire("internal/etat/etat.go")


def test_l5_marqueur_d_allegement_lu():
    """R-L5-34 : Interface = distante d'après le marqueur root de l'allègement réussi (lecture seule)."""
    code = sans_commentaires(lire("apparmor/usr.sbin.sbx-pilotage-agent"))
    for r in ("/var/lib/secubox-profiles/ r,", "/var/lib/secubox-profiles/allegement/ r,",
              "/var/lib/secubox-profiles/allegement/actif r,"):
        assert r in code, r
    assert "/var/lib/secubox-profiles/allegement/** " not in code
