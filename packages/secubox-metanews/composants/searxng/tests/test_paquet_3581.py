# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3581 — paquet : conteneur LXC en trixie non privilégié, SearXNG au commit figé et dépendances à empreintes, aucun
sudoers, API au socle de durcissement complet, reload par unité .path + oneshot root (exception écrite), AppArmor, aucune
exposition publique, installation par debian/rules, postinst sans création du LXC."""
import json
import re
import shutil
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
UNITE_RELOAD = (COMPOSANT / "debian" / "secubox-searxng-reload.service").read_text(encoding="utf-8")
PATH_RELOAD = (COMPOSANT / "debian" / "secubox-searxng-reload.path").read_text(encoding="utf-8")


def _code(texte):
    return [x for x in texte.splitlines() if not x.lstrip().startswith("#")]


def _unite(texte):
    u = {}
    for x in texte.splitlines():
        if "=" in x and not x.startswith("#"):
            k, v = x.split("=", 1)
            u.setdefault(k, []).append(v)
    return u


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


# ── Aucun sudoers ; API au socle complet ; reload par unité .path + oneshot root ──

def test_aucun_sudoers():
    assert not (COMPOSANT / "sudoers.d").exists()
    for f in (PAQUET / "debian" / "rules", COMPOSANT / "debian" / "postinst"):
        assert "sudoers.d/secubox-searxng" not in "\n".join(_code(f.read_text())), f
    assert '"--acteur-stdin"' not in CTL and '"sudo"' not in CTL and '"/usr/bin/systemd-run"' not in CTL


def test_unite_api_socle_complet_sans_exception():
    u = _unite(UNITE)
    assert u["User"] == ["secubox-searxng"] and u["Group"] == ["secubox"] and u["UMask"] == ["0027"]
    assert u["SupplementaryGroups"] == ["secubox-searxng"]
    for k in ("NoNewPrivileges", "ProtectHome", "PrivateTmp", "PrivateDevices", "ProtectKernelTunables", "ProtectKernelModules",
              "ProtectKernelLogs", "ProtectControlGroups", "ProtectClock", "ProtectHostname", "RestrictSUIDSGID",
              "RestrictNamespaces", "RestrictRealtime", "LockPersonality"):
        assert u[k] == ["yes"], k
    assert u["ProtectSystem"] == ["strict"] and u["SystemCallArchitectures"] == ["native"]
    assert u["CapabilityBoundingSet"] == [""] and u["AmbientCapabilities"] == [""]
    assert u["RestrictAddressFamilies"] == ["AF_UNIX AF_INET"]
    assert u["AppArmorProfile"] == ["secubox-searxng-api"] and u["ReadWritePaths"] == ["/run/secubox /var/log/secubox"]
    assert u["IPAddressDeny"] == ["any"] and u["IPAddressAllow"] == ["10.100.0.85/32"]
    assert u["ExecStartPre"] == ["+/bin/rm -f /run/secubox/searxng.sock", "+/usr/sbin/searxngctl preparer"]
    assert "--uds /run/secubox/searxng.sock" in u["ExecStart"][0]
    assert "RuntimeDirectory" not in u
    regles = (RACINE / ".claude" / "RULES-CODE.md").read_text(encoding="utf-8")
    assert not [x for x in regles.splitlines() if x.startswith("| § 10 durcissement | `secubox-searxng.service`")]


def test_unite_reload_root_et_exception_ecrite():
    p = _unite(PATH_RELOAD)
    assert p["PathExistsGlob"] == ["/run/secubox/searxng-reload/*.demande"]
    assert p["Unit"] == ["secubox-searxng-reload.service"] and p["WantedBy"] == ["paths.target"]
    u = _unite(UNITE_RELOAD)
    assert u["Type"] == ["oneshot"] and "User" not in u
    assert u["ExecStart"] == ["/usr/sbin/searxngctl reload --demandes"]
    assert u["UMask"] == ["0027"] and u["PrivateTmp"] == ["yes"] and u["ProtectHome"] == ["yes"]
    assert u["IPAddressDeny"] == ["any"] and u["IPAddressAllow"] == ["10.100.0.85/32"]
    assert u["TimeoutStartSec"] == ["10min"]
    # lxc-attach (setns, cgroup du conteneur, personnalité, profil AppArmor à l'exécution) : options absentes, écrites.
    for k in ("NoNewPrivileges", "ProtectSystem", "ProtectKernelTunables", "ProtectControlGroups", "RestrictNamespaces",
              "RestrictSUIDSGID", "LockPersonality"):
        assert k not in u, k
    regles = (RACINE / ".claude" / "RULES-CODE.md").read_text(encoding="utf-8")
    ligne = [x for x in regles.splitlines() if "`secubox-searxng-reload.service`" in x]
    assert len(ligne) == 1 and "§ 10" in ligne[0] and "test_unite_reload_root_et_exception_ecrite" in ligne[0]


def test_profil_apparmor():
    p = (COMPOSANT / "apparmor" / "secubox-searxng-api").read_text()
    code = "\n".join(_code(p))
    assert "profile secubox-searxng-api {" in p and "sudo" not in code and " Ux," not in code and " ux," not in code
    assert "deny /etc/secubox/secrets/** rwklx," in p and "/run/secubox/searxng.sock rwk," in p
    assert "/etc/secubox/searxng.toml r," in p and "/var/cache/secubox-searxng/** rwk," in p
    assert not re.search(r"^\s*/etc/secubox/\*\*", p, re.M) and " ix," not in p.replace("rix,", "")
    # Journaux : seulement ceux de secubox_core, jamais audit.log.
    assert "deny /var/log/secubox/audit.log w," in p and "/var/log/secubox/*.log" not in code
    ecrits = re.findall(r"^\s*(/var/log/secubox/\S+) \w*w\w*,", code, re.M)
    assert sorted(ecrits) == ["/var/log/secubox/delegation.log", "/var/log/secubox/garde-origine.log"]
    assert "owner /run/secubox/searxng-reload/* rw," in p and "/run/secubox/searxng-reload-resultats/*.json r," in p


def test_profil_apparmor_compile():
    if not shutil.which("apparmor_parser") or not Path("/etc/apparmor.d/tunables/global").exists():
        pytest.skip("apparmor_parser absent")
    subprocess.run(["apparmor_parser", "-QT", str(COMPOSANT / "apparmor" / "secubox-searxng-api")], check=True, timeout=60,
                   capture_output=True)


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


def test_menu_dans_la_section_des_services():
    m = json.loads((COMPOSANT / "menu.d" / "60-searxng.json").read_text())
    assert m["id"] == "searxng" and m["path"] == "/searxng/"
    assert (m["category"], m["theme"]) == ("mesh", "veille")
    espaces = json.loads((RACINE / "packages" / "secubox-hub" / "espaces.json").read_text())
    assert espaces["modules"]["searxng"] == {"espace": "services", "objet": "SERVICE"}
    assert "yacy" not in espaces["modules"]


# ── debian/rules, postinst, version ──

def test_debian_rules_installe_le_composant():
    rules = (PAQUET / "debian" / "rules").read_text()
    for cible in ("usr/lib/secubox/searxng/", "usr/sbin/searxngctl", "usr/share/secubox/lib/searxng/installer-searxng.sh",
                  "usr/share/secubox/searxng/searxng.toml.example", "usr/share/secubox/www/searxng/index.html",
                  "usr/share/secubox/menu.d/60-searxng.json", "etc/nginx/secubox-routes.d/searxng.conf",
                  "etc/apparmor.d/secubox-searxng-api",
                  "usr/lib/systemd/system/secubox-searxng.service",
                  "usr/lib/systemd/system/secubox-searxng-reload.service",
                  "usr/lib/systemd/system/secubox-searxng-reload.path", "maintscripts/searxng.postinst",
                  "maintscripts/searxng.prerm", "maintscripts/searxng.postrm"):
        assert cible in rules, cible
    assert "sudoers" not in "\n".join(x for x in rules.splitlines() if "searxng" in x)
    assert "dh_installsystemd --name=secubox-searxng" not in rules      # le postinst du composant l'active, après le compte
    assert "python3-yaml" in (PAQUET / "debian" / "control").read_text()


def test_postinst_ne_cree_pas_le_conteneur():
    p = (COMPOSANT / "debian" / "postinst").read_text()
    code = "\n".join(_code(p))
    assert "lxc-create" not in code and "searxngctl install" not in code
    assert "adduser --system --ingroup secubox --no-create-home --home /nonexistent" in code and "secubox-searxng" in code
    assert "apparmor_parser -r /etc/apparmor.d/secubox-searxng-api" in code and "visudo" not in code
    assert 'deb-systemd-helper --quiet was-enabled "$_u"' in code and "systemctl restart secubox-searxng.service" in code
    assert "for _u in secubox-searxng.service secubox-searxng-reload.path; do" in code
    assert "systemctl restart secubox-searxng-reload.path" in code
    assert "addgroup --system secubox-searxng" in code and "/usr/sbin/searxngctl preparer" in code
    assert "install -d -m 0700 -o root -g root /var/lib/secubox-searxng" in code
    # Le TOML : root propriétaire, jamais inscriptible par le groupe (searxngctl le refuserait).
    assert "install -m 0640 -o root -g secubox /usr/share/secubox/searxng/searxng.toml.example /etc/secubox/searxng.toml" in code
    prerm = (COMPOSANT / "debian" / "prerm").read_text()
    assert "systemctl stop secubox-searxng-reload.path secubox-searxng.service" in prerm


def test_dossier_du_conteneur_reste_root(ctl, cfg, tmp_path, monkeypatch):
    assert "os.chown(racine, UID_RACINE" not in CTL
    racine = tmp_path / "lxc" / "searxng"
    (racine / "rootfs").mkdir(parents=True)
    cfg = {"lxc": {**cfg["lxc"], "path": str(tmp_path / "lxc")}, "searxng": cfg["searxng"]}
    vus = []
    monkeypatch.setattr(ctl.os, "fchown", lambda fd, u, g: vus.append((u, g)))
    monkeypatch.setattr(ctl, "executer", lambda argv, **kw: vus.append(tuple(argv[:2])))
    # Un lien laissé sous le nom du temporaire n'est jamais suivi : la cible reste intacte.
    cible = tmp_path / "cible"
    cible.write_text("intact\n")
    (racine / "config.secubox.tmp").symlink_to(cible)
    ctl.creer_conteneur(cfg)
    assert cible.read_text() == "intact\n" and not (racine / "config.secubox.tmp").exists()
    assert "lxc.idmap = u 0 100000 65536" in (racine / "config").read_text()
    assert (racine / "config").stat().st_mode & 0o777 == 0o640 and racine.stat().st_mode & 0o777 == 0o755
    assert vus == [(0, 0)]                                # dossier du conteneur : root:root, jamais l'idmap
    # Le rootfs seul est décalé sur l'idmap (une fois, sans suivre les liens).
    assert '["chown", "-R", "-h", f"{UID_RACINE}:{UID_RACINE}", str(racine / "rootfs")]' in CTL


def test_tmp_de_config_en_o_excl_nofollow(ctl):
    assert "os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o640" in CTL


def test_dossier_des_secrets_cree_root_0700(ctl, tmp_path, monkeypatch):
    monkeypatch.setattr(ctl, "SECRETS", tmp_path / "secrets" / "searxng")
    monkeypatch.setattr(ctl.os, "chown", lambda *a: None)
    ctl.secret_cle()
    assert (tmp_path / "secrets").stat().st_mode & 0o777 == 0o700
    (tmp_path / "secrets").chmod(0o750)                   # existant (partagé) : jamais retouché
    ctl.secret_cle()
    assert (tmp_path / "secrets").stat().st_mode & 0o777 == 0o750


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
