# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3581 — retrait de YaCy sur une box déjà installée : rm_conffile pour chaque ancien fichier de configuration, et un bloc
du postinst de secubox-metanews qui n'agit QUE pour une mise à jour depuis une version << 0.6.0, sans jamais supprimer de
données (conteneur, rootfs, TOML, état, secrets), sans toucher HAProxy ni le WAF. Le bloc est exécuté pour de vrai, dans
une arborescence temporaire, avec des commandes simulées (nginx, systemctl)."""
import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest

PAQUET = Path(__file__).resolve().parents[3]
POSTINST = (PAQUET / "debian" / "postinst").read_text(encoding="utf-8")
MAINTSCRIPT = (PAQUET / "debian" / "secubox-metanews.maintscript").read_text(encoding="utf-8")
BLOC = POSTINST.split("# >>> retrait-yacy (#3581)\n", 1)[1].split("# <<< retrait-yacy\n", 1)[0]

# Anciens fichiers de configuration de YaCy : ceux que l'ancien debian/rules installait sous /etc.
ANCIENS_CONFFILES = ("/etc/sudoers.d/secubox-yacy", "/etc/nginx/secubox-routes.d/yacy.conf", "/etc/nginx/secubox.d/yacy.conf",
                     "/etc/nginx/sites-available/yacy.conf", "/etc/secubox/yacy.toml.example")


def test_rm_conffile_pour_chaque_ancien_fichier():
    lignes = [x.split() for x in MAINTSCRIPT.splitlines() if x and not x.startswith("#")]
    assert sorted(lignes) == sorted(["rm_conffile", f, "0.6.0-1~"] for f in ANCIENS_CONFFILES)
    rules = (PAQUET / "debian" / "rules").read_text(encoding="utf-8")
    assert "yacy" not in rules.lower()                                     # plus rien de YaCy n'est livré


def test_bloc_borne_a_la_mise_a_jour_depuis_avant_0_6_0():
    assert 'if [ "$1" = configure ] && [ -n "${2:-}" ] && dpkg --compare-versions "$2" lt "0.6.0-1~"; then' in BLOC
    assert BLOC.rstrip().endswith("fi")


def test_aucune_suppression_de_donnees_ni_haproxy_ni_waf():
    code = "\n".join(x for x in BLOC.splitlines() if not x.lstrip().startswith("#"))
    for interdit in ("rm -rf", "rm -r ", "lxc-destroy", "lxc-stop", "lxc-attach", "rmdir", "/var/lib/secubox/yacy",
                     "secrets", "deluser", "haproxyctl vhost remove yacy", "secubox-waf-route", "haproxy-routes.json",
                     "systemctl restart haproxy", "systemctl reload haproxy"):
        assert interdit not in code, interdit
    # Seule suppression : le lien du vhost dans sites-enabled.
    assert re.findall(r"\brm -f [^\n]*", code) == ['rm -f "$_y_lien"']
    assert "haproxyctl vhost remove" in code and "generate --allow-shrink" in code   # dit, jamais fait (echo)
    assert all("haproxyctl" not in x or x.lstrip().startswith("echo ") for x in code.splitlines())


def _bac_a_sable(tmp_path: Path, nginx_ok: bool = True, avec_toml: bool = True):
    r = tmp_path / "racine"
    for d in ("etc/nginx/sites-enabled", "etc/nginx/sites-available", "etc/secubox/secrets", "run/systemd/system",
              "srv/lxc/yacy/rootfs/opt", "var/lib/secubox/yacy", "data/lxc/yacy"):
        (r / d).mkdir(parents=True)
    (r / "etc/nginx/sites-available/autre.conf").write_text("server {}\n")
    (r / "etc/nginx/sites-enabled/yacy.conf").symlink_to(r / "etc/nginx/sites-available/yacy.conf")
    (r / "etc/nginx/sites-enabled/autre.conf").symlink_to(r / "etc/nginx/sites-available/autre.conf")
    if avec_toml:
        (r / "etc/secubox/yacy.toml").write_text(
            '[lxc]\nname         = "yacy"   # nom\nip = "10.100.0.80"\npath = "%s/srv/lxc"\n[peer]\npeer_name = "x"\n' % r)
    (r / "etc/secubox/secrets/yacy-admin").write_text("s\n")
    (r / "var/lib/secubox/yacy/etat").write_text("e\n")
    conf = r / ("srv/lxc/yacy/config" if avec_toml else "data/lxc/yacy/config")
    conf.write_text("lxc.uts.name = yacy\nlxc.start.auto = 1\nlxc.start.delay = 5\n")
    (r / "srv/lxc/yacy/rootfs/opt/index").write_text("index\n")
    outils = tmp_path / "outils"
    outils.mkdir()
    journal = tmp_path / "appels"
    for nom, code in (("nginx", 0 if nginx_ok else 1), ("systemctl", 0), ("haproxyctl", 0), ("lxc-stop", 0)):
        f = outils / nom
        f.write_text(f'#!/bin/sh\necho "{nom} $*" >> "{journal}"\nexit {code}\n')
        f.chmod(0o755)
    # Le bloc, avec ses chemins absolus rabattus dans l'arborescence temporaire.
    bloc = BLOC
    for chemin in ("/etc/", "/data/lxc", "/var/backups", "/run/systemd/system"):
        bloc = bloc.replace(chemin, f"{r}{chemin}")
    script = tmp_path / "bloc.sh"
    script.write_text("set -e\n" + bloc)
    return r, conf, outils, journal, script


def _lancer(script, outils, *args):
    env = {**os.environ, "PATH": f"{outils}:{os.environ['PATH']}"}
    return subprocess.run(["sh", str(script), *args], env=env, capture_output=True, text=True, timeout=30, check=True)


@pytest.mark.skipif(shutil.which("dpkg") is None, reason="dpkg --compare-versions requis")
@pytest.mark.parametrize("args", [("configure", ""), ("configure", "0.6.0-1~trixie1"), ("configure", "0.6.1-1~trixie1"),
                                  ("abort-upgrade", "0.5.5-1~trixie1"), ("triggered", "x")])
def test_rien_hors_mise_a_jour_depuis_avant_0_6_0(tmp_path, args):
    r, conf, outils, journal, script = _bac_a_sable(tmp_path)
    avant = {p: (p.is_symlink(), p.read_text() if p.is_file() else None) for p in r.rglob("*")}
    p = _lancer(script, outils, *args)
    assert {p: (p.is_symlink(), p.read_text() if p.is_file() else None) for p in r.rglob("*")} == avant
    assert not journal.exists() and p.stdout == "" and p.stderr == ""


@pytest.mark.skipif(shutil.which("dpkg") is None, reason="dpkg --compare-versions requis")
def test_mise_a_jour_depuis_0_5_nettoie_sans_rien_supprimer(tmp_path):
    r, conf, outils, journal, script = _bac_a_sable(tmp_path)
    p = _lancer(script, outils, "configure", "0.5.5-1~trixie1")
    assert not (r / "etc/nginx/sites-enabled/yacy.conf").is_symlink()
    assert (r / "etc/nginx/sites-enabled/autre.conf").is_symlink()                 # les autres vhosts restent
    assert journal.read_text().splitlines() == ["nginx -t", "systemctl reload nginx"]  # testé avant de recharger
    c = conf.read_text()
    assert c.count("lxc.start.auto") == 1 and "lxc.start.auto = 0\n" in c and "lxc.start.delay = 5" in c
    # Données intactes : conteneur, rootfs, TOML, état, secrets.
    assert (r / "srv/lxc/yacy/rootfs/opt/index").read_text() == "index\n"
    assert (r / "etc/secubox/yacy.toml").exists() and (r / "var/lib/secubox/yacy/etat").read_text() == "e\n"
    assert (r / "etc/secubox/secrets/yacy-admin").read_text() == "s\n"
    assert "haproxyctl vhost remove" in p.stdout and "--allow-shrink" in p.stdout


@pytest.mark.skipif(shutil.which("dpkg") is None, reason="dpkg --compare-versions requis")
def test_nginx_refuse_pas_de_rechargement_et_chemin_par_defaut(tmp_path):
    r, conf, outils, journal, script = _bac_a_sable(tmp_path, nginx_ok=False, avec_toml=False)
    conf.write_text("lxc.uts.name = yacy\n")                                     # sans lxc.start.auto : ajouté à 0
    p = _lancer(script, outils, "configure", "0.5.4-1~trixie1")
    assert journal.read_text().splitlines() == ["nginx -t"] and "NON rechargé" in p.stderr
    assert conf.read_text() == "lxc.uts.name = yacy\nlxc.start.auto = 0\n"       # /data/lxc/yacy par défaut


@pytest.mark.skipif(shutil.which("dpkg") is None, reason="dpkg --compare-versions requis")
def test_copie_posee_a_la_main_mise_de_cote_et_lien_de_config_ignore(tmp_path):
    r, conf, outils, journal, script = _bac_a_sable(tmp_path)
    lien = r / "etc/nginx/sites-enabled/yacy.conf"
    lien.unlink()
    lien.write_text("server { server_name yacy.exemple; }\n")
    cible = tmp_path / "ailleurs"
    cible.write_text("lxc.start.auto = 1\n")
    conf.unlink()
    conf.symlink_to(cible)                                                     # un lien n'est jamais suivi
    _lancer(script, outils, "configure", "0.5.5-1~trixie1")
    assert not lien.exists()
    assert (r / "var/backups/secubox-vhosts/yacy.conf.avant-retrait").read_text() == "server { server_name yacy.exemple; }\n"
    assert cible.read_text() == "lxc.start.auto = 1\n"


def test_postinst_syntaxe():
    subprocess.run(["sh", "-n", str(PAQUET / "debian" / "postinst")], check=True, timeout=10)


def test_manifeste_searxng_manuel():
    racine = PAQUET.parents[1]
    m = (racine / "board" / "mochabin" / "modules.d" / "searxng.toml").read_text(encoding="utf-8")
    assert 'id        = "searxng"' in m and 'lifecycle = "manual"' in m and 'lxc       = "searxng"' in m
    assert 'exposure  = "internal"' in m and "portal" not in "\n".join(x for x in m.splitlines() if not x.startswith("#"))
    assert not (racine / "board" / "mochabin" / "modules.d" / "yacy.toml").exists()


def test_wiki_searxng_a_la_place_de_yacy():
    racine = PAQUET.parents[1]
    for d in ("wiki", "docs/wiki"):
        for langue in ("EN", "FR", "DE", "ZH"):
            t = (racine / d / f"MODULES-{langue}.md").read_text(encoding="utf-8")
            assert "| 🔎 **SearXNG** | Network |" in t and "#### 🔎 SearXNG" in t, (d, langue)
            assert "**YaCy**" not in t and "#### 🔎 YaCy" not in t, (d, langue)
