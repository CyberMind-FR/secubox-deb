# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3581 — paquet : conteneur LXC en trixie non privilégié, SearXNG au commit figé, sudoers sans joker, unité durcie et son
exception écrite, AppArmor, aucune exposition publique, installation par debian/rules, postinst sans création du LXC."""
import json
import re
import subprocess
from pathlib import Path

import pytest

COMPOSANT = Path(__file__).resolve().parents[1]
PAQUET = COMPOSANT.parents[1]
RACINE = PAQUET.parents[1]
COMMIT = "3e95f6cd2a68add0329cb162907b49289e2bc1fd"
CTL = (COMPOSANT / "sbin" / "searxngctl").read_text(encoding="utf-8")
INSTALLEUR = (COMPOSANT / "lib" / "searxng" / "installer-searxng.sh").read_text(encoding="utf-8")
UNITE = (COMPOSANT / "debian" / "secubox-searxng.service").read_text(encoding="utf-8")


def _code(texte):
    return [x for x in texte.splitlines() if not x.lstrip().startswith("#")]


# ── LXC : Pattern 11, dernière Debian, non privilégié ──

def test_aucune_suite_bookworm_en_dur():
    for nom, texte in (("searxngctl", CTL), ("installer-searxng.sh", INSTALLEUR)):
        assert not [x for x in _code(texte) if "bookworm" in x], nom
    for texte in (CTL, INSTALLEUR):                                  # Pattern 11 : LXC, jamais Docker ni Podman
        assert not re.search(r"""["']?(docker|podman)["']?\s*(run|pull|create|,)""", texte, re.I)
    assert '["lxc-create", "-n", lxc["name"], "-t", "download"' in CTL


@pytest.mark.parametrize("contenu,attendu", [("ID=debian\nVERSION_CODENAME=trixie\n", "trixie"),
                                             ('ID=debian\nVERSION_CODENAME="forky"\n', "forky"),
                                             ("ID=ubuntu\nVERSION_CODENAME=noble\n", "trixie"), (None, "trixie")])
def test_suite_de_l_hote_repli_trixie(ctl, tmp_path, monkeypatch, contenu, attendu):
    monkeypatch.delenv("SECUBOX_DEBIAN_SUITE", raising=False)
    f = tmp_path / "os-release"
    if contenu is not None:
        f.write_text(contenu)
    assert ctl.suite_debian(str(f)) == attendu
    monkeypatch.setenv("SECUBOX_DEBIAN_SUITE", "forky")
    assert ctl.suite_debian(str(f)) == "forky"


def test_config_lxc_non_privilegiee_bornee_et_reecrite(ctl, cfg):
    ancienne = ("lxc.net.0.type = veth\nlxc.net.0.link = lxcbr0\nlxc.cgroup2.cpu.max = 200000 100000\n"
                "lxc.cgroup2.cpu.weight = 50\nlxc.mount.entry = /etc etc none bind 0 0\n")
    c = ctl.config_lxc(cfg, ancienne)
    assert "lxc.idmap = u 0 100000 65536" in c and "lxc.idmap = g 0 100000 65536" in c
    assert "lxc.start.auto = 1" in c and "lxc.cgroup2.memory.max = 384M" in c and "lxc.cgroup2.memory.high = 320M" in c
    assert "lxc.net.0.ipv4.address = 10.100.0.85/24" in c and "lxc.net.0.link = br-lxc" in c
    assert "lxc.rootfs.path = dir:/data/lxc/searxng/rootfs" in c
    assert c.count("lxc.net.0.type") == 1 and "lxcbr0" not in c and "lxc.mount.entry" not in c   # réécrit, jamais ajouté
    assert "lxc.cgroup2.cpu.max = 200000 100000" in c and "lxc.cgroup2.cpu.weight = 50" in c      # plafonds de tuning repris
    assert ctl.config_lxc(cfg, c) == c                                                          # idempotent


def test_chemin_lxc_lu_dans_la_configuration(ctl, cfg):
    cfg = {"lxc": {**cfg["lxc"], "path": "/srv/lxc"}, "searxng": cfg["searxng"]}
    assert "lxc.rootfs.path = dir:/srv/lxc/searxng/rootfs" in ctl.config_lxc(cfg)
    assert ctl.Conteneur(cfg)._attache() == ["lxc-attach", "-n", "searxng", "-P", "/srv/lxc", "--"]


def test_searxng_au_commit_fige_dans_un_venv():
    assert f'COMMIT = "{COMMIT}"' in CTL and 'DEPOT = "https://github.com/searxng/searxng"' in CTL
    assert '"$SEARXNG_COMMIT" =~ ^[0-9a-f]{40}$' in INSTALLEUR
    assert 'fetch -q --depth 1 "$SEARXNG_DEPOT" "$SEARXNG_COMMIT"' in INSTALLEUR
    assert 'rev-parse HEAD' in INSTALLEUR and '[[ "$obtenu" == "$SEARXNG_COMMIT" ]]' in INSTALLEUR
    assert '-r "$SRC/requirements.txt"' in INSTALLEUR and '-r "$SRC/requirements-server.txt"' in INSTALLEUR
    assert "python3 -m venv" in INSTALLEUR and "useradd --system" in INSTALLEUR and "User=searxng" in INSTALLEUR
    assert "--host $SEARXNG_IP --port $SEARXNG_PORT" in INSTALLEUR and not [x for x in _code(INSTALLEUR) if "0.0.0.0" in x]
    assert "EnvironmentFile=/etc/searxng/searxng.env" in INSTALLEUR and "SEARXNG_SECRET=" not in INSTALLEUR


def test_secret_jamais_sur_argv_ni_dans_le_toml(ctl):
    # Le secret passe par l'entrée standard (Conteneur.ecrire) en 0600 ; jamais en argument de lxc-attach.
    assert 'ct.ecrire(ENVIRONNEMENT, contenu, mode="0600")' in CTL
    assert 'SECRETS = Path("/etc/secubox/secrets/searxng")' in CTL and "O_EXCL" in CTL and "0o600" in CTL
    assert not [x for x in _code((COMPOSANT / "conf" / "searxng.toml.example").read_text()) if "secret" in x.lower()]


def test_secret_cree_une_fois(ctl, tmp_path, monkeypatch):
    monkeypatch.setattr(ctl, "SECRETS", tmp_path / "searxng")
    monkeypatch.setattr(ctl.os, "chown", lambda *a: None)
    a = ctl.secret_cle()
    assert re.fullmatch(r"[0-9a-f]{64}", a) and ctl.secret_cle() == a
    f = tmp_path / "searxng" / "secret_key"
    assert f.stat().st_mode & 0o777 == 0o600 and (tmp_path / "searxng").stat().st_mode & 0o777 == 0o700


def test_scripts_syntaxe():
    subprocess.run(["bash", "-n", str(COMPOSANT / "lib" / "searxng" / "installer-searxng.sh")], check=True, timeout=10)
    for s in ("postinst", "prerm", "postrm"):
        subprocess.run(["sh", "-n", str(COMPOSANT / "debian" / s)], check=True, timeout=10)
    compile(CTL, "searxngctl", "exec")
    assert CTL.startswith("#!/usr/bin/python3 -I\n")


# ── sudoers, unité, AppArmor ──

def test_sudoers_sans_joker_ni_shell():
    lignes = [x for x in (COMPOSANT / "sudoers.d" / "secubox-searxng").read_text().splitlines() if x and not x.startswith("#")]
    assert lignes == ["secubox-searxng ALL=(root) NOPASSWD: /usr/bin/systemd-run --wait --pipe --collect --quiet "
                      "/usr/sbin/searxngctl reload --json --acteur-stdin"]
    for interdit in ("*", "?", "[", "ALL=(ALL)", "sh ", "bash", "lxc-", "NOPASSWD: ALL", "!"):
        assert interdit not in lignes[0].split("NOPASSWD:", 1)[1], interdit


def test_unite_durcie_et_exception_ecrite():
    u = {}
    for x in UNITE.splitlines():
        if "=" in x and not x.startswith("#"):
            k, v = x.split("=", 1)
            u.setdefault(k, []).append(v)
    assert u["User"] == ["secubox-searxng"] and u["Group"] == ["secubox"] and u["UMask"] == ["0027"]
    assert u["NoNewPrivileges"] == ["no"] and u["ProtectSystem"] == ["strict"] and u["ProtectHome"] == ["yes"]
    assert u["PrivateTmp"] == ["yes"] and u["ProtectControlGroups"] == ["yes"]
    assert u["AppArmorProfile"] == ["secubox-searxng-api"] and u["ReadWritePaths"] == ["/run/secubox /var/log/secubox"]
    assert u["IPAddressDeny"] == ["any"] and u["IPAddressAllow"] == ["10.100.0.0/24"]
    assert "+/bin/rm -f /run/secubox/searxng.sock" in u["ExecStartPre"]
    assert "--uds /run/secubox/searxng.sock" in u["ExecStart"][0]
    assert "RuntimeDirectory" not in u
    # Options à filtre seccomp : elles imposeraient NoNewPrivileges et neutraliseraient sudo.
    for k in ("ProtectKernelTunables", "ProtectKernelModules", "LockPersonality", "RestrictSUIDSGID", "SystemCallFilter",
              "RestrictNamespaces", "RestrictAddressFamilies", "PrivateDevices", "MemoryDenyWriteExecute"):
        assert k not in u, k
    regles = (RACINE / ".claude" / "RULES-CODE.md").read_text(encoding="utf-8")
    ligne = [x for x in regles.splitlines() if "`secubox-searxng.service`" in x]
    assert len(ligne) == 1 and "§ 10" in ligne[0] and "test_unite_durcie_et_exception_ecrite" in ligne[0]


def test_profil_apparmor():
    p = (COMPOSANT / "apparmor" / "secubox-searxng-api").read_text()
    assert "profile secubox-searxng-api {" in p and "/usr/bin/sudo Ux," in p
    assert "deny /etc/secubox/secrets/** rwklx," in p and "/run/secubox/searxng.sock rwk," in p
    assert "/etc/secubox/searxng.toml r," in p and "/var/cache/secubox-searxng/** rwk," in p
    assert not re.search(r"^\s*/etc/secubox/\*\*", p, re.M) and " ix," not in p.replace("rix,", "")


# ── Exposition : interne seulement ──

def test_aucune_exposition_publique():
    route = (COMPOSANT / "nginx" / "searxng.conf").read_text()
    code = "\n".join(_code(route))
    assert "server_name" not in code and "listen" not in code and "error_page" not in code
    assert "location /api/v1/searxng/ {" in code and "proxy_pass http://unix:/run/secubox/searxng.sock;" in code
    for f in COMPOSANT.rglob("*"):
        if f.is_file() and "tests" not in f.parts and f.suffix in ("", ".py", ".sh", ".conf", ".toml", ".example", ".json"):
            t = f.read_text(encoding="utf-8", errors="replace")
            assert "haproxy-routes.json" not in t and "haproxyctl" not in t and "secubox-waf-route" not in t, f
    rules = (PAQUET / "debian" / "rules").read_text()
    assert "sites-available/searxng" not in rules and "searxng-vhost" not in rules


def test_menu_dans_la_section_de_yacy():
    m = json.loads((COMPOSANT / "menu.d" / "60-searxng.json").read_text())
    yacy = json.loads((PAQUET / "composants" / "yacy" / "menu.d" / "60-yacy.json").read_text())
    assert m["id"] == "searxng" and m["path"] == "/searxng/"
    assert (m["category"], m["theme"]) == (yacy["category"], yacy["theme"])
    espaces = json.loads((RACINE / "packages" / "secubox-hub" / "espaces.json").read_text())
    assert espaces["modules"]["searxng"] == espaces["modules"].get("yacy", {"espace": "services", "objet": "SERVICE"})


# ── debian/rules, postinst, version ──

def test_debian_rules_installe_le_composant():
    rules = (PAQUET / "debian" / "rules").read_text()
    for cible in ("usr/lib/secubox/searxng/", "usr/sbin/searxngctl", "usr/share/secubox/lib/searxng/installer-searxng.sh",
                  "usr/share/secubox/searxng/searxng.toml.example", "usr/share/secubox/www/searxng/index.html",
                  "usr/share/secubox/menu.d/60-searxng.json", "etc/nginx/secubox-routes.d/searxng.conf",
                  "etc/sudoers.d/secubox-searxng", "etc/apparmor.d/secubox-searxng-api",
                  "usr/lib/systemd/system/secubox-searxng.service", "maintscripts/searxng.postinst",
                  "maintscripts/searxng.prerm", "maintscripts/searxng.postrm"):
        assert cible in rules, cible
    assert "install -D -m 440 composants/searxng/sudoers.d/secubox-searxng" in rules
    assert "dh_installsystemd --name=secubox-searxng" not in rules      # le postinst du composant l'active, après le compte
    assert "python3-yaml" in (PAQUET / "debian" / "control").read_text()


def test_postinst_ne_cree_pas_le_conteneur():
    p = (COMPOSANT / "debian" / "postinst").read_text()
    code = "\n".join(_code(p))
    assert "lxc-create" not in code and "searxngctl install" not in code
    assert "adduser --system --ingroup secubox --no-create-home --home /nonexistent" in code and "secubox-searxng" in code
    assert "apparmor_parser -r /etc/apparmor.d/secubox-searxng-api" in code and "visudo -cf" in code
    assert 'deb-systemd-helper --quiet was-enabled "$_u"' in code and "systemctl restart secubox-searxng.service" in code
    assert "install -d -m 0700 -o root -g root /var/lib/secubox-searxng" in code


def test_version_et_changelog():
    tete, signature = (PAQUET / "debian" / "changelog").read_text(encoding="utf-8").split("\n -- ", 1)
    assert tete.startswith("secubox-metanews (0.6.0-1~trixie1) trixie;") and "(ref #3581)" in tete
    assert signature.splitlines()[0].endswith("Thu, 12 Nov 2026 12:00:00 +0100")


def test_en_tetes_spdx():
    for f in COMPOSANT.rglob("*"):
        if f.is_file() and "__pycache__" not in f.parts and f.suffix != ".json":
            assert "SPDX-License-Identifier: LicenseRef-CMSD-1.0" in f.read_text(encoding="utf-8")[:600], f


def test_agregateur_ne_le_monte_jamais():
    agr = (RACINE / "packages" / "secubox-aggregator" / "aggregator" / "main.py").read_text(encoding="utf-8")
    bloc = agr.split("DEDICATED_MODULES = frozenset({", 1)[1].split("})", 1)[0]
    assert '"searxng"' in bloc
    mig = (RACINE / "packages" / "secubox-aggregator" / "sbin" / "secubox-aggregator-migrate").read_text(encoding="utf-8")
    ligne = [x for x in mig.splitlines() if x.startswith("readonly AGG_EXCLUDE=")][0]
    assert "searxng" in ligne.split('"')[1].split()
