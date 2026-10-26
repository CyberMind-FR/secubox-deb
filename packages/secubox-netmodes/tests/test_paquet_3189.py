# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3189 — paquet 1.4.0 : unités, sudoers à verbes exacts, profils AppArmor, scripts de maintenance, exception écrite."""
import fnmatch
import json
import os
import re
import shutil
import subprocess
from pathlib import Path
from unittest import mock

import pytest
from fastapi.testclient import TestClient

import secubox_core.config as _cfg

_cfg._CONFIG = {"global": {}, "api": {"socket_dir": "/tmp/secubox", "jwt_secret": "test"}, "auth": {"users": {}}}
with mock.patch("pathlib.Path.mkdir"):
    from api import main, routeur_api, routeur_ctl  # noqa: E402

from api.routeur_rendu import CHEMINS  # noqa: E402
from secubox_core.auth import require_jwt, require_lecture  # noqa: E402

PKG = Path(__file__).resolve().parents[1]
DEPOT = PKG.parents[1]
CTL = "/usr/sbin/netmodesctl"
TESTS = "packages/secubox-netmodes/tests/test_paquet_3189.py::"
TEST_EXCEPTION = TESTS + "test_unite_api_durcie_et_exception"
# Options qui posent un filtre seccomp : sous User= non root, systemd active alors NoNewPrivileges d'office et sudo répond
# « no new privileges flag is set » (mesuré sur gk2 et gk3 : secubox-ad-guard-auto.service, secubox-voicestudio-api.service).
SECCOMP = ("ProtectKernelTunables", "LockPersonality", "RestrictSUIDSGID", "SystemCallFilter", "SystemCallArchitectures",
           "RestrictNamespaces", "RestrictAddressFamilies", "MemoryDenyWriteExecute", "PrivateDevices",
           "ProtectKernelModules", "ProtectKernelLogs", "ProtectClock", "ProtectHostname", "RestrictRealtime",
           "RestrictFileSystems", "DynamicUser")


def lire(chemin: str) -> str:
    return (PKG / chemin).read_text(encoding="utf-8")


def unite(chemin: str) -> dict[str, list[str]]:
    """Directives d'une unité (commentaires ignorés, lignes continuées jointes) : clé -> valeurs dans l'ordre."""
    d: dict[str, list[str]] = {}
    texte = re.sub(r"\\\n\s*", " ", lire(chemin))
    for ligne in texte.splitlines():
        ligne = ligne.strip()
        if not ligne or ligne[0] in "#;[" or "=" not in ligne:
            continue
        cle, valeur = ligne.split("=", 1)
        d.setdefault(cle.strip(), []).append(valeur.strip())
    return d


def chemins_rw(u: dict[str, list[str]]) -> set[str]:
    return {c.lstrip("-") for v in u.get("ReadWritePaths", []) for c in v.split()}


def sans_commentaires(texte: str) -> str:
    return "\n".join(ligne for ligne in texte.splitlines() if not ligne.lstrip().startswith("#"))


def ligne_exception(nom_unite: str) -> str:
    """La ligne de RULES-CODE.md § Exceptions dont la colonne « Exception » commence par cette unité (une seule)."""
    regles = (DEPOT / ".claude/RULES-CODE.md").read_text(encoding="utf-8")
    lignes = [ligne for ligne in regles.splitlines()
              if ligne.startswith("|") and ligne.count(" | ") >= 3 and ligne.split(" | ")[1].startswith(f"`{nom_unite}`")]
    assert len(lignes) == 1, lignes
    return lignes[0]


# --- unité de l'API ----------------------------------------------------------------------------------------------------

def test_unite_api_durcie_et_exception():
    u = unite("debian/secubox-netmodes.service")
    for cle, valeur in {"User": "secubox-netmodes", "Group": "secubox", "UMask": "0027", "NoNewPrivileges": "no",
                        "ProtectSystem": "strict", "ProtectHome": "yes", "PrivateTmp": "yes",
                        "ProtectControlGroups": "yes", "AppArmorProfile": "secubox-netmodes-api",
                        "KillMode": "process", "StateDirectory": "secubox-netmodes-api",
                        "StateDirectoryMode": "0750"}.items():
        assert u.get(cle) == [valeur], (cle, u.get(cle))
    # sudo vers netmodesctl : rien qui impose NoNewPrivileges, plus de capacité ambiante (l'API n'en a jamais eu besoin)
    for cle in SECCOMP + ("AmbientCapabilities", "RuntimeDirectory"):
        assert cle not in u, cle
    # le contrôleur root lancé par sudo hérite de cet espace de montage : chaque dossier qu'il écrit doit y être ouvert
    rw = chemins_rw(u)
    for chemin in ("/run/secubox", "/run/lock", "/var/lib/secubox-netmodes",
                   "/var/log/secubox", "/etc/systemd/network", "/etc/secubox/netmodes", "/etc/unbound/unbound.conf.d",
                   "/etc/nftables.d", "/etc/nginx/secubox-lan-geo.d", "/var/lib/misc"):
        assert chemin in rw, chemin
    # rien sous /var/lib/secubox (compte partagé secubox), rien que seul nginx -t demandait (il passe par systemd-run)
    assert not any(c == "/var/lib/secubox" or c.startswith("/var/lib/secubox/") for c in rw), rw
    assert "/run" not in rw and "/var/log/nginx" not in rw
    # socket : § 2 et MODULE-COMPLIANCE § Socket
    assert u["ExecStartPre"] == ["+/bin/rm -f /run/secubox/netmodes.sock"]
    assert "--uds /run/secubox/netmodes.sock" in u["ExecStart"][0]
    assert any("chmod 660 /run/secubox/netmodes.sock" in v for v in u.get("ExecStartPost", []))
    # l'exception est écrite, avec sa raison et ce test
    ligne = ligne_exception("secubox-netmodes.service")
    for mot in ("NoNewPrivileges=no", "KillMode=process", "ReadWritePaths", "netmodesctl", TEST_EXCEPTION):
        assert mot in ligne, mot


@pytest.mark.parametrize("fichier", ["debian/secubox-netmodes.service", "debian/secubox-netmodes-retour-boot.service"])
def test_unite_couvre_chaque_ecriture_du_controleur(fichier):
    """Croisé avec le code : tout dossier où netmodesctl écrit est ouvert, sinon EROFS en pleine bascule ou au retour."""
    rw = chemins_rw(unite(fichier))
    ecrits = {os.path.dirname(c) for c in CHEMINS.values()}
    ecrits |= {os.path.dirname(c) for c in (routeur_ctl.TOML, routeur_ctl.ANCIEN_PONT, routeur_ctl.AUDIT,
                                            routeur_ctl.VERROU, routeur_ctl.VERROU_UNBOUND, routeur_ctl.BAUX)}
    ecrits |= {routeur_ctl.ARBRE}
    for dossier in sorted(ecrits):
        assert any(dossier == c or dossier.startswith(c + "/") for c in rw), dossier


def test_nginx_t_du_controleur_hors_du_bac_a_sable():
    """`nginx -t` ouvre en écriture /run/nginx.pid et ses journaux : lancé par sudo DANS l'espace de montage de l'API il
    échouerait toujours. Le contrôleur le passe à systemd-run (contexte de PID 1) ; l'unité n'ouvre donc ni /run ni
    /var/log/nginx."""
    assert routeur_ctl.NGINX_T == ["systemd-run", "--wait", "--pipe", "--collect", "--quiet", "/usr/sbin/nginx", "-t"]
    rw = chemins_rw(unite("debian/secubox-netmodes.service"))
    assert "/run" not in rw and "/var/log/nginx" not in rw


def test_etat_des_anciens_modes_hors_du_compte_partage():
    """L'état des anciens modes (nom du mode) quitte /var/lib/secubox, dossier du compte partagé secubox : un lien posé
    là aurait détourné les opérations root du postinst. StateDirectory le crée au compte de l'API ; surtout pas
    « secubox-netmodes », que systemd réattribuerait alors que c'est l'arbre root seul du contrôleur."""
    assert main.STATE_FILE == Path("/var/lib/secubox-netmodes-api/state.json")
    u = unite("debian/secubox-netmodes.service")
    assert u["StateDirectory"] == ["secubox-netmodes-api"] and u["StateDirectoryMode"] == ["0750"]
    assert Path(routeur_ctl.ARBRE).name not in u["StateDirectory"][0].split()
    r = regles_aa("apparmor/secubox-netmodes")
    assert "/var/lib/secubox-netmodes-api/ r," in r and "/var/lib/secubox-netmodes-api/** rwk," in r
    assert not any(ligne.startswith("/var/lib/secubox/") and not ligne.endswith(" r,") for ligne in r), r


def test_unite_api_apres_les_dependances_et_sans_bytecode():
    u = unite("debian/secubox-netmodes.service")
    assert "PYTHONDONTWRITEBYTECODE=1" in " ".join(u.get("Environment", []))
    assert u["WorkingDirectory"] == ["/usr/lib/secubox/netmodes"]


# --- DHCP du LAN et retour au démarrage --------------------------------------------------------------------------------

def test_unite_lan_dhcp_root_confinee():
    u = unite("debian/secubox-lan-dhcp.service")
    # relecture finale I7 : Type=exec, `systemctl restart` échoue si l'exec échoue ; le contrôleur vérifie ensuite que
    # dnsmasq reste actif (refus AppArmor, port pris : sinon l'application serait déclarée réussie)
    assert u["Type"] == ["exec"]
    assert u["ExecStart"] == ["/usr/sbin/dnsmasq --keep-in-foreground --conf-file=/var/lib/secubox-netmodes/lan-dhcp.conf"
                              " --pid-file="]
    assert CHEMINS["dhcp"] == "/var/lib/secubox-netmodes/lan-dhcp.conf"   # le fichier rendu est bien celui-là
    assert "systemd-networkd.service" in u["After"][0].split()
    for cle, valeur in {"Restart": "on-failure", "ProtectSystem": "strict", "ReadWritePaths": "/var/lib/misc",
                        "ProtectHome": "yes", "PrivateTmp": "yes", "ProtectKernelTunables": "yes",
                        "ProtectControlGroups": "yes", "AppArmorProfile": "secubox-lan-dhcp",
                        "NoNewPrivileges": "yes"}.items():
        assert u.get(cle) == [valeur], (cle, u.get(cle))
    assert set(u["CapabilityBoundingSet"][0].split()) == {"CAP_NET_ADMIN", "CAP_NET_BIND_SERVICE", "CAP_NET_RAW",
                                                          "CAP_SETUID", "CAP_SETGID", "CAP_CHOWN"}
    assert u["WantedBy"] == ["multi-user.target"]                         # le contrôleur l'active : [Install] requis
    assert "User" not in u                                                # root le temps de lire la conf root seule
    for cle in ("RestrictSUIDSGID", "LockPersonality"):
        assert u.get(cle) == ["yes"], cle
    # root : exception écrite, avec ce test
    ligne = ligne_exception("secubox-lan-dhcp.service")
    for mot in ("user=dnsmasq", "AppArmor", "CapabilityBoundingSet", TESTS + "test_unite_lan_dhcp_root_confinee"):
        assert mot in ligne, mot


def test_unite_retour_boot_root_durcie():
    u = unite("debian/secubox-netmodes-retour-boot.service")
    assert u["Type"] == ["oneshot"]
    # avant le DHCP du LAN : après un redémarrage, jamais de bail servi sur un sous-réseau non confirmé
    assert set(u["After"][0].split()) == {"systemd-networkd.service", "nftables.service", "unbound.service"}
    assert u["Before"] == ["secubox-lan-dhcp.service"]
    assert not any("network-online" in v for k in ("After", "Wants", "Requires") for v in u.get(k, []))
    # root sans sudo ni AppArmor : tout le socle § 10 sauf User=, chemins du contrôleur seulement
    for cle, valeur in {"NoNewPrivileges": "yes", "ProtectSystem": "strict", "ProtectHome": "yes", "PrivateTmp": "yes",
                        "ProtectKernelTunables": "yes", "ProtectControlGroups": "yes", "RestrictSUIDSGID": "yes",
                        "LockPersonality": "yes", "UMask": "0027"}.items():
        assert u.get(cle) == [valeur], (cle, u.get(cle))
    assert "User" not in u and "AppArmorProfile" not in u
    api = unite("debian/secubox-netmodes.service")
    assert sorted(" ".join(u["ReadWritePaths"]).split()) == sorted(" ".join(api["ReadWritePaths"]).split())
    ligne = ligne_exception("secubox-netmodes-retour-boot.service")
    for mot in ("ProtectSystem", "ReadWritePaths", "netmodesctl", TESTS + "test_unite_retour_boot_root_durcie"):
        assert mot in ligne, mot
    assert u["ExecStart"] == [f"{CTL} routeur-retour-demarrage"]
    # le contrôleur attend jusqu'à 60 s son verrou puis peut passer 120 s par commande
    assert int(u["TimeoutStartSec"][0]) >= routeur_ctl.DELAI_VERROU_RETOUR + 120
    assert u["WantedBy"] == ["multi-user.target"]


# --- sudoers -----------------------------------------------------------------------------------------------------------

LIGNE_SUDOERS = ("secubox-netmodes ALL=(root) NOPASSWD: /usr/sbin/netmodesctl routeur-etat, "
                 "/usr/sbin/netmodesctl routeur-appliquer *, /usr/sbin/netmodesctl routeur-confirmer *, "
                 "/usr/sbin/netmodesctl routeur-retour *")


def regles_sudoers() -> list[str]:
    return [ligne for ligne in sans_commentaires(lire("debian/secubox-netmodes.sudoers")).splitlines() if ligne.strip()]


def test_sudoers_ligne_exacte():
    assert regles_sudoers() == [LIGNE_SUDOERS]


@pytest.mark.skipif(not shutil.which("visudo"), reason="visudo absent")
def test_sudoers_valide_par_visudo():
    r = subprocess.run(["visudo", "-cf", str(PKG / "debian/secubox-netmodes.sudoers")], capture_output=True,
                       text=True, timeout=30, check=False)
    assert r.returncode == 0, r.stdout + r.stderr


def autorisations() -> list[tuple[str, list[str]]]:
    """(commande, arguments en motif) de chaque grant de la ligne sudoers."""
    utilisateur, reste = regles_sudoers()[0].split(" ", 1)
    assert utilisateur == "secubox-netmodes"
    hote, commandes = reste.split(" NOPASSWD: ", 1)
    assert hote == "ALL=(root)"
    sortie = []
    for cmd in commandes.split(", "):
        mots = cmd.split(" ")
        sortie.append((mots[0], mots[1:]))
    return sortie


def accorde(argv: list[str]) -> bool:
    """Correspondance façon sudo : commande exacte ; arguments joints par une espace, `*` couvre tout, espaces comprises."""
    for commande, motif in autorisations():
        if argv[0] != commande:
            continue
        if not motif:
            return True                                                   # sans argument : tout argument permis
        if motif == ['""']:
            return len(argv) == 1
        if fnmatch.fnmatchcase(" ".join(argv[1:]), " ".join(motif)):
            return True
    return False


class Faux:
    def __init__(self, reponses):
        self.reponses = list(reponses)
        self.appels = []

    def __call__(self, argv, **kw):
        self.appels.append(argv)
        code, sortie = self.reponses.pop(0)
        return subprocess.CompletedProcess(argv, code, stdout=json.dumps(sortie), stderr="")


def test_sudoers_conforme_aux_appels_de_l_api(monkeypatch):
    """Croisé avec test_routeur_api_3189.py::test_argv_conformes_au_sudoers : les argv qu'émet l'API sont exactement
    ceux que la ligne accorde ; un verbe sans `*` est appelé sans argument, un verbe à `*` avec un seul acteur."""
    grants = autorisations()
    assert all(c == CTL for c, _ in grants)
    sans_acteur = {m[0] for _, m in grants if len(m) == 1}
    avec_acteur = {m[0] for _, m in grants if len(m) == 2 and m[1] == "*"}
    assert len(grants) == len(sans_acteur) + len(avec_acteur)
    # le contrôleur : mêmes verbes ; le retour au démarrage n'est jamais accordé (unité root seulement)
    ctl = (PKG / "sbin/netmodesctl").read_text(encoding="utf-8")
    assert avec_acteur == set(re.search(r"AVEC_ACTEUR = \(([^)]*)\)", ctl).group(1).replace('"', "").replace(" ", "")
                              .strip(",").split(","))
    assert sans_acteur == {"routeur-etat"} and "routeur-retour-demarrage" not in sans_acteur | avec_acteur

    main.app.dependency_overrides[require_jwt] = lambda: {"sub": "alice"}
    main.app.dependency_overrides[require_lecture] = lambda: {"sub": "alice"}
    monkeypatch.setattr(routeur_api, "est_mochabin", lambda: False)
    etat = {"etat": "actif", "adresses_pont": ["192.168.42.1/24"]}
    faux = Faux([(0, etat), (0, etat), (0, {}), (0, {}), (0, {})])
    monkeypatch.setattr(routeur_api.subprocess, "run", faux)
    try:
        client = TestClient(main.app, base_url="http://testserver")
        client.get("/routeur/etat")
        client.post("/routeur/appliquer", json={"adresse": "192.168.77.1/24", "dhcp_debut": "192.168.77.100",
                                                "dhcp_fin": "192.168.77.199", "confirmer": "routeur"})
        client.post("/routeur/confirmer")
        client.post("/routeur/retour", json={"confirmer": "retour"})
    finally:
        main.app.dependency_overrides.clear()
    assert len(faux.appels) == 5
    verbes = set()
    for argv in faux.appels:
        assert argv[:2] == ["sudo", "-n"], argv
        cmd = argv[2:]
        assert accorde(cmd), cmd
        verbe = cmd[1]
        verbes.add(verbe)
        if verbe in sans_acteur:
            assert len(cmd) == 2, cmd                                     # aucun argument : la règle n'en tolère aucun
        else:
            assert verbe in avec_acteur and len(cmd) == 3 and routeur_ctl.ACTEUR.fullmatch(cmd[2]), cmd
    assert verbes == sans_acteur | avec_acteur                            # rien d'accordé qui ne serve
    # et ce que la règle refuse
    assert not accorde([CTL, "routeur-etat", "alice"])
    assert not accorde([CTL, "routeur-appliquer"])
    assert not accorde([CTL, "routeur-retour-demarrage"])


# --- contrôle, version, scripts ----------------------------------------------------------------------------------------

def test_control_depends_et_version():
    ctl = lire("debian/control")
    depends = re.search(r"^Depends:(.*(?:\n .*)*)", ctl, re.M).group(1)
    deps = {d.strip().split(" ")[0] for d in depends.replace("\n", " ").split(",")}
    for d in ("python3", "python3-yaml", "python3-jinja2", "dnsmasq-base", "nftables", "sudo", "apparmor",
              "secubox-core", "iproute2"):
        assert d in deps, d
    assert re.search(r"python3 \(>= 3\.11\)", depends)                    # tomllib
    assert "Architecture: all" in ctl and "Standards-Version: 4.6.2" in ctl and "debhelper-compat (= 13)" in ctl
    tete = lire("debian/changelog").split("\n -- ", 1)
    assert tete[0].startswith("secubox-netmodes (1.4.0-1~trixie1) trixie; urgency=medium")
    assert "(ref #3189)" in tete[0]
    assert tete[1].startswith("Gérald Kerma <devel@cybermind.fr>  Mon, 26 Oct 2026 14:00:00 +0100")


@pytest.mark.parametrize("script", ["postinst", "prerm"])
def test_scripts_debian_posix(script):
    texte = lire(f"debian/{script}")
    assert texte.startswith("#!/bin/sh\n")
    assert "SPDX-License-Identifier: LicenseRef-CMSD-1.0" in texte
    assert subprocess.run(["sh", "-n", str(PKG / "debian" / script)], timeout=30, check=False).returncode == 0
    assert "#DEBHELPER#" in texte


def test_postinst():
    p = re.sub(r"\\\n\s*", " ", sans_commentaires(lire("debian/postinst")))      # lignes continuées jointes
    assert re.search(r"adduser --system --ingroup secubox .*secubox-netmodes", p)
    assert "install -d -m 0700 -o root -g root /var/lib/secubox-netmodes" in p
    # aucune opération root sous /var/lib/secubox (dossier du compte partagé secubox : un lien y détournerait root)
    assert "/var/lib/secubox/" not in p
    assert not re.search(r"\b(install|chown|chmod|mv|rm|ln|mkdir|cp)\b[^\n]*/var/lib/secubox\b(?!-)", p)
    assert "visudo -cf /etc/sudoers.d/secubox-netmodes" in p
    assert "rm -f /etc/sudoers.d/secubox-netmodes" in p                  # jamais de sudoers cassé laissé en place
    for profil in ("secubox-netmodes", "secubox-lan-dhcp"):
        assert f"apparmor_parser -r /etc/apparmor.d/{profil}" in p, profil
    assert "systemctl enable secubox-netmodes-retour-boot.service" in p
    assert "systemctl restart secubox-netmodes.service" in p
    # le profil est chargé AVANT de (re)démarrer l'API qui le nomme
    assert p.index("apparmor_parser -r /etc/apparmor.d/secubox-netmodes") < p.index(
        "systemctl restart secubox-netmodes.service")
    # le DHCP du LAN n'est jamais démarré par le paquet : c'est la bascule du contrôleur qui le fait
    assert not re.search(r"systemctl (enable|start|restart)[^\n]*secubox-lan-dhcp", p)
    # jamais de netplan ni de relance d'interface
    assert "netplan" not in p and not re.search(r"\bip link\b", p)


def test_prerm_arrete_l_api_et_laisse_le_lan():
    p = sans_commentaires(lire("debian/prerm"))
    assert "systemctl stop secubox-netmodes.service" in p
    assert "secubox-lan-dhcp" not in p and "br-lan" not in p and "nft " not in p


# --- AppArmor ----------------------------------------------------------------------------------------------------------

def regles_aa(chemin: str) -> list[str]:
    return [ligne.strip() for ligne in sans_commentaires(lire(chemin)).splitlines() if ligne.strip()]


def test_profil_api():
    r = regles_aa("apparmor/secubox-netmodes")
    assert "profile secubox-netmodes-api {" in r
    for regle in ("/usr/bin/sudo Ux,", "/usr/lib/secubox/netmodes/** r,", "/etc/secubox/netmodes/** r,",
                  "/proc/device-tree/model r,", "/sys/firmware/devicetree/base/model r,",
                  "/run/secubox/netmodes.sock rwk,", "/var/lib/secubox-netmodes-api/** rwk,", "/var/log/secubox/*.log w,",
                  "deny /etc/secubox/secrets/** r,"):
        assert regle in r, regle
    texte = "\n".join(r)
    assert "/etc/secubox/** " not in texte                                # jamais tout /etc/secubox (les secrets y sont)
    assert "/usr/sbin/netmodesctl" not in texte                           # seulement par sudo, hors confinement
    # le processus de l'API n'exécute aucun shell (seule la détection, dans son sous-profil, en a un)
    principal = texte.split("profile net_detect", 1)[0]
    assert not re.search(r"/(ba|da)?sh\b", principal)


def test_profil_dnsmasq():
    r = regles_aa("apparmor/secubox-lan-dhcp")
    assert "profile secubox-lan-dhcp {" in r
    for regle in ("/usr/sbin/dnsmasq mr,", "/var/lib/secubox-netmodes/lan-dhcp.conf r,",
                  "/var/lib/misc/dnsmasq.leases* rw,", "/etc/passwd r,", "/etc/group r,", "/etc/nsswitch.conf r,"):
        assert regle in r, regle
    # capacités du profil == bornes de l'unité
    caps = {c for ligne in r if ligne.startswith("capability ") for c in ligne[11:].rstrip(",").split()}
    borne = unite("debian/secubox-lan-dhcp.service")["CapabilityBoundingSet"][0].split()
    assert caps == {c.removeprefix("CAP_").lower() for c in borne}
    texte = "\n".join(r)
    assert "/etc/secubox" not in texte and " ix," not in texte and " ux," not in texte.lower()


@pytest.mark.skipif(not shutil.which("apparmor_parser") or not Path("/etc/apparmor.d/tunables/global").exists(),
                    reason="apparmor_parser ou ses abstractions absents")
@pytest.mark.parametrize("profil", ["secubox-netmodes", "secubox-lan-dhcp"])
def test_profils_analyses_par_apparmor_parser(profil):
    # -Q : rien n'est chargé dans le noyau ; -K -T : aucun cache lu ni écrit
    r = subprocess.run(["apparmor_parser", "-Q", "-K", "-T", str(PKG / "apparmor" / profil)], capture_output=True,
                       text=True, timeout=60, check=False)
    assert r.returncode == 0, r.stderr


# --- debian/rules ------------------------------------------------------------------------------------------------------

def test_rules_installe_controleur_sudoers_profils_et_unites():
    rules = lire("debian/rules")
    p = "debian/secubox-netmodes"
    assert f"install -m 0755 sbin/netmodesctl {p}/usr/sbin/" in rules
    assert f"install -m 0440 debian/secubox-netmodes.sudoers {p}/etc/sudoers.d/secubox-netmodes" in rules
    assert f"install -m 0644 apparmor/secubox-netmodes {p}/etc/apparmor.d/secubox-netmodes" in rules
    assert f"install -m 0644 apparmor/secubox-lan-dhcp {p}/etc/apparmor.d/secubox-lan-dhcp" in rules
    assert "dh_installsystemd --name=secubox-netmodes\n" in rules
    assert "dh_installsystemd --name=secubox-net-fallback --no-enable --no-start" in rules
    assert "dh_installsystemd --name=secubox-lan-dhcp --no-enable --no-start" in rules
    assert re.search(r"dh_installsystemd --name=secubox-netmodes-retour-boot --no-start\n", rules)
    for source in ("sbin/netmodesctl", "debian/secubox-netmodes.sudoers", "apparmor/secubox-netmodes",
                   "apparmor/secubox-lan-dhcp", "debian/secubox-lan-dhcp.service",
                   "debian/secubox-netmodes-retour-boot.service"):
        assert (PKG / source).is_file(), source


@pytest.mark.parametrize("fichier", ["debian/secubox-lan-dhcp.service", "debian/secubox-netmodes-retour-boot.service",
                                     "debian/secubox-netmodes.service", "debian/secubox-netmodes.sudoers",
                                     "apparmor/secubox-netmodes", "apparmor/secubox-lan-dhcp", "debian/rules"])
def test_entete_spdx(fichier):
    assert "SPDX-License-Identifier: LicenseRef-CMSD-1.0" in lire(fichier)


def test_readme_mode_routeur():
    r = lire("README.md")
    assert "## Mode routeur durable (MOCHAbin)" in r
    for mot in ("/etc/secubox/netmodes/routeur.toml", "routeur-appliquer", "routeur-confirmer", "routeur-retour",
                "routeur-retour-demarrage", "/routeur/appliquer", "/routeur/confirmer", "/routeur/retour",
                "/routeur/etat", "/routeur/apercu", "3 minutes", "secubox-lan-dhcp", CHEMINS["dhcp"],
                *CHEMINS.values()):
        assert mot in r, mot
