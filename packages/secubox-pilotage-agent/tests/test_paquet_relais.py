# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3126 L5 tâche 2 : contrôles statiques du relais `sbx-pilotage-relais` (unités, AppArmor, règles, scripts du paquet).

R-L5-9, R-L5-13, R-L5-18 : compte dédié `secubox-pilotage-relais`, seul lecteur de la clé privée
(/var/lib/secubox-pilotage-relais/relais.key, 0600) ; clé publique /etc/secubox-pilotage/relais.pub posée par le
postinst (root:root 0644, dossier root 0755) ; socket /run/secubox/pilotage-relais.sock 0660, groupe de l'agent."""
import re
import shutil
import subprocess
from pathlib import Path

RACINE = Path(__file__).resolve().parents[1]
SERVICE = "systemd/secubox-pilotage-relais.service"
SOCKET = "systemd/secubox-pilotage-relais.socket"
PROFIL = "apparmor/usr.sbin.sbx-pilotage-relais"


def lire(rel):
    return (RACINE / rel).read_text(encoding="utf-8")


def sans_commentaires(txt):
    return "\n".join(ligne for ligne in txt.splitlines() if not ligne.lstrip().startswith("#"))


def directives(rel):
    d = {}
    for ligne in sans_commentaires(lire(rel)).splitlines():
        if "=" in ligne:
            k, v = ligne.split("=", 1)
            d.setdefault(k.strip(), []).append(v.strip())
    return d


def test_socket_du_relais_reservee_a_l_agent():
    d = directives(SOCKET)
    assert d["ListenStream"] == ["/run/secubox/pilotage-relais.sock"]
    assert d["SocketMode"] == ["0660"]
    assert d["SocketUser"] == ["secubox-pilotage-relais"]
    assert d["SocketGroup"] == ["secubox-pilotage-agent"]
    assert d["Service"] == ["secubox-pilotage-relais.service"]
    assert d["RemoveOnStop"] == ["yes"]
    assert "Accept" not in d   # un seul processus, qui contrôle SO_PEERCRED lui-même
    assert "DirectoryMode" not in d   # /run/secubox est partagé (1777) : jamais recréé ni modifié ici


def test_unite_du_relais_durcie():
    d = directives(SERVICE)
    attendu = {
        "User": "secubox-pilotage-relais", "Group": "secubox-pilotage-relais", "ExecStart": "/usr/sbin/sbx-pilotage-relais",
        "AppArmorProfile": "/usr/sbin/sbx-pilotage-relais", "NoNewPrivileges": "yes", "ProtectSystem": "strict",
        "ProtectHome": "yes", "PrivateTmp": "yes", "PrivateDevices": "yes", "PrivateNetwork": "yes",
        "ProtectKernelTunables": "yes", "ProtectKernelModules": "yes", "ProtectKernelLogs": "yes",
        "ProtectControlGroups": "yes", "ProtectClock": "yes", "RestrictSUIDSGID": "yes", "LockPersonality": "yes",
        "RestrictNamespaces": "yes", "RestrictRealtime": "yes", "MemoryDenyWriteExecute": "yes",
        "SystemCallArchitectures": "native", "RestrictAddressFamilies": "AF_UNIX", "IPAddressDeny": "any",
        "UMask": "0077", "CapabilityBoundingSet": "", "AmbientCapabilities": "",
        # Les modules servent leurs sockets en 0660 groupe secubox (RULES-CODE § 2) : le relais doit s'y connecter.
        "SupplementaryGroups": "secubox",
        "ReadWritePaths": "-/var/log/secubox",
        "Requires": "secubox-pilotage-relais.socket",
        # R-L5-19 (minor 7) : aucun vidage mémoire (clé privée), /proc des autres processus invisible.
        "LimitCORE": "0", "ProtectProc": "invisible",
        # Ajout à audit.log : l'ACL est reposée à chaque démarrage (la rotation recrée le fichier sans elle).
        "ExecStartPre": "-+/usr/sbin/secubox-pilotage-relais-acl",
    }
    for k, v in attendu.items():
        assert d.get(k) == [v], (k, d.get(k))
    # /run/secubox est partagé : ni RuntimeDirectory (systemd l'effacerait à l'arrêt), ni rm de la socket (systemd la crée).
    assert "RuntimeDirectory" not in d
    # La clé privée n'est jamais écrite par le service (créée par le postinst) : son dossier n'est pas inscriptible.
    assert "StateDirectory" not in d
    assert "secubox-pilotage-relais.socket" in d["After"][0].split()


def test_gomemlimit_sous_memorymax():
    d = directives(SERVICE)
    assert d["MemoryMax"] == ["64M"] and d["Environment"] == ["GOMEMLIMIT=48MiB"]


def test_apparmor_du_relais():
    code = sans_commentaires(lire(PROFIL))
    assert re.search(r"^/usr/sbin/sbx-pilotage-relais \{", code, re.M)
    assert "#include <abstractions/base>" in lire(PROFIL)
    # Réseau : sockets Unix seulement, jamais inet.
    assert re.search(r"^\s*network \([^)]*\) unix stream,", code, re.M)
    assert "inet" not in code
    # R-L5-19 (I1) : le drapeau des mains liées est lu dans l'arbre root, JAMAIS sous /etc/secubox (compte secubox).
    assert "/etc/secubox/pilotage" not in code
    for regle in ("/etc/secubox-pilotage/mains-liees r,",
                  "/var/lib/secubox-pilotage-relais/relais.key rl,", "/etc/secubox-pilotage/relais.pub r,",
                  "/run/secubox/*.sock rw,", "/var/log/secubox/audit.log w,", "@{PROC}/sys/kernel/hostname r,",
                  "deny /etc/secubox/secrets/** rwx,", "deny /etc/shadow r,"):
        assert regle in code, regle
    # Aucun exécutable lancé, aucune capacité.
    assert not re.search(r"\b[ipuPUc]x\b", code) and "capability" not in code


def test_regles_installent_le_relais():
    r = lire("debian/rules")
    assert "install -D -m 0755 sbin/secubox-pilotage-relais-acl $(P)/usr/sbin/secubox-pilotage-relais-acl" in r
    assert "go build -ldflags \"-s -w -X main.version=$(VERSION)\" -o debian/sbx-pilotage-relais ./cmd/sbx-pilotage-relais" in r
    for m in ("install -D -m 0755 debian/sbx-pilotage-relais $(P)/usr/sbin/sbx-pilotage-relais",
              f"install -D -m 0644 {SERVICE} $(P)/lib/systemd/system/secubox-pilotage-relais.service",
              f"install -D -m 0644 {SOCKET} $(P)/lib/systemd/system/secubox-pilotage-relais.socket",
              f"install -D -m 0644 {PROFIL} $(P)/etc/apparmor.d/usr.sbin.sbx-pilotage-relais",
              "dh_installsystemd --name=secubox-pilotage-relais --no-enable --no-start"):
        assert m in r, m


def test_postinst_compte_cles_et_activation():
    p = sans_commentaires(lire("debian/postinst"))
    for m in ("adduser --system --no-create-home --group secubox-pilotage-relais",
              "install -d -o secubox-pilotage-relais -g secubox-pilotage-relais -m 0700 /var/lib/secubox-pilotage-relais",
              "install -d -o root -g root -m 0755 /etc/secubox-pilotage",
              "apparmor_parser -r /etc/apparmor.d/usr.sbin.sbx-pilotage-relais",
              "runuser -u secubox-pilotage-relais -- /usr/sbin/sbx-pilotage-relais cle-publique",
              "chown root:root", "chmod 0644", "/etc/secubox-pilotage/relais.pub",
              "systemctl enable --now secubox-pilotage-relais.socket",
              "/usr/sbin/secubox-pilotage-relais-acl"):
        assert m in p, m
    # Minor 9 : la socket n'est activée que si la clé publique est posée.
    bloc = p[p.index("relais_pret="):]
    assert 'if [ "$relais_pret" = 1 ]' in bloc and bloc.index('if [ "$relais_pret" = 1 ]') < bloc.index(
        "systemctl enable --now secubox-pilotage-relais.socket")
    assert "[ -s /etc/secubox-pilotage/relais.pub ]" in p
    # Mise à niveau : l'état root des mains liées est projeté dans l'arbre du relais.
    assert "/var/lib/secubox-pilotagectl/mains-liees" in p and "/etc/secubox-pilotage/mains-liees" in p
    # La clé publique n'est posée qu'après le chargement du profil, et par root (jamais par le relais).
    assert p.index("apparmor_parser -r /etc/apparmor.d/usr.sbin.sbx-pilotage-relais") < p.index("runuser -u")
    # Jamais la clé privée dans le postinst : il ne la lit ni ne la copie.
    assert "relais.key" not in p
    assert "systemctl stop secubox-pilotage-relais.socket" in lire("debian/prerm")
    assert "systemctl stop secubox-pilotage-relais.service" in lire("debian/prerm")
    po = lire("debian/postrm")
    assert "apparmor_parser -R /etc/apparmor.d/usr.sbin.sbx-pilotage-relais" in po
    assert "rm -rf /var/lib/secubox-pilotage-relais" in po and "rm -f /etc/secubox-pilotage/relais.pub" in po


def test_scripts_debian_posix():
    sh = shutil.which("sh")
    for rel in ("debian/postinst", "debian/prerm", "debian/postrm"):
        assert lire(rel).startswith("#!/bin/sh\n"), rel
        if sh:
            subprocess.run([sh, "-n", str(RACINE / rel)], check=True, timeout=10, capture_output=True, text=True)


def test_version_montee_et_dependance_au_verificateur():
    assert lire("debian/changelog").startswith("secubox-pilotage-agent (0.5.1-1~trixie1) trixie;")
    c = lire("debian/control")
    # Le vérificateur Ed25519 (tâche 1) est dans secubox-core 1.8.11.
    assert "secubox-core (>= 1.8.11~)" in re.search(r"^Depends:(.*)$", c, re.M).group(1)


def test_entetes_spdx_du_relais():
    fichiers = [SERVICE, SOCKET, PROFIL] + [str(f.relative_to(RACINE)) for f in (RACINE / "internal" / "relais").glob("*.go")]
    for rel in fichiers:
        assert "LicenseRef-CMSD-1.0" in lire(rel), rel


def _banc_acl(tmp_path, monkeypatch):
    bin_ = tmp_path / "bin"
    bin_.mkdir()
    appels = tmp_path / "appels"
    faux = bin_ / "setfacl"
    faux.write_text(f'#!/bin/sh\necho "$@" >> {appels}\nls -lL "$3" >> {appels}\n', encoding="utf-8")
    faux.chmod(0o755)
    journal = tmp_path / "audit.log"
    journal.write_text("")
    import os
    import pwd
    nom = pwd.getpwuid(os.getuid()).pw_name
    env = {**os.environ, "PATH": f"{bin_}:/usr/bin:/bin"}
    def lancer(*args):
        return subprocess.run(["python3", "-I", str(RACINE / "sbin/secubox-pilotage-relais-acl"), "--fichier", str(journal),
                               "--proprietaire", nom, *args], env=env, capture_output=True, text=True, timeout=30)
    return journal, appels, lancer


def test_acl_audit_posee_sur_le_fichier_verifie(tmp_path, monkeypatch):
    """Minor 6 : comme secubox-pilotage-audit-acl — fichier ouvert O_NOFOLLOW, vérifié sur le descripteur,
    ACL d'ÉCRITURE seule (l'ajout O_APPEND du relais) posée sur /proc/self/fd/N."""
    journal, appels, lancer = _banc_acl(tmp_path, monkeypatch)
    r = lancer()
    assert r.returncode == 0, r.stderr
    ligne = appels.read_text().splitlines()[0]
    assert ligne.startswith("-m u:secubox-pilotage-relais:-w- /proc/self/fd/"), ligne


def test_acl_audit_refusee_sur_lien_ou_autre_proprietaire(tmp_path, monkeypatch):
    journal, appels, lancer = _banc_acl(tmp_path, monkeypatch)
    cible = tmp_path / "secret"
    cible.write_text("")
    journal.unlink()
    journal.symlink_to(cible)
    assert lancer().returncode == 1
    journal.unlink()
    journal.write_text("")
    r = subprocess.run(["python3", "-I", str(RACINE / "sbin/secubox-pilotage-relais-acl"), "--fichier", str(journal),
                        "--proprietaire", "root"], capture_output=True, text=True, timeout=30)
    import os
    if os.getuid() != 0:
        assert r.returncode == 1
    assert not appels.exists()
    # Journal absent (box neuve) : rien à faire, succès.
    journal.unlink()
    assert lancer().returncode == 0
