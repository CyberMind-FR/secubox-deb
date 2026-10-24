# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""#3117 : les vhosts livrés ne portent aucun nom propre à une box."""
from pathlib import Path

PKG = Path(__file__).resolve().parent.parent
SOURCES = [PKG / "nginx" / "actor.vhost.conf",
           PKG / "composants" / "waf" / "nginx" / "waf-vhost.conf"]
RULES = (PKG / "debian" / "rules").read_text(encoding="utf-8")


def test_aucun_nom_de_gk2_dans_les_vhosts():
    for f in SOURCES:
        assert "gk2" not in f.read_text(encoding="utf-8"), f


def test_server_name_generique():
    for f, attendu in zip(SOURCES, ("server_name actor.*;", "server_name waf.*;")):
        assert attendu in f.read_text(encoding="utf-8")


def test_noms_installes_neutres():
    assert "sites-available/actor.conf" in RULES
    assert "sites-available/waf.conf" in RULES
    assert "gk2" not in "".join(l for l in RULES.splitlines() if "sites-available" in l)


def test_postinst_active_les_nouveaux_noms_et_migre():
    for p in (PKG / "debian" / "postinst", PKG / "composants" / "waf" / "debian" / "postinst"):
        t = p.read_text(encoding="utf-8")
        assert "sbx_migrer_vhost" in t
        assert 'ln -sf' in t
    assert 'A_VHOST="actor"' in (PKG / "debian" / "postinst").read_text(encoding="utf-8")
    assert 'VHOST="waf"' in (PKG / "composants/waf/debian/postinst").read_text(encoding="utf-8")


MIGRATIONS = [
    (PKG / "debian" / "postinst", "actor.gk2.secubox.in.conf", "actor.conf"),
    (PKG / "composants" / "waf" / "debian" / "postinst", "waf.gk2.secubox.in.conf", "waf.conf"),
]


# ── Migration : un ancien vhost retouché est archivé, jamais recopié ───────
import hashlib
import os
import re
import stat
import subprocess


def _fonction(chemin: Path) -> str:
    t = chemin.read_text(encoding="utf-8")
    m = re.search(r"^[ ]*sbx_migrer_vhost\(\) \{\n.*?\n[ ]*\}\n", t, re.S | re.M)
    assert m, chemin
    return m.group(0)


def _lancer(tmp_path: Path, chemin: Path, ancien: str, nouveau: str, md5_livre: str,
            snip_ancien: str = "", snip_nouveau: str = ""):
    racine = tmp_path
    f = (_fonction(chemin).replace("/etc/nginx", f"{racine}/etc/nginx")
         .replace("/var/backups", f"{racine}/var/backups"))
    bin_ = tmp_path / "bin"; bin_.mkdir(exist_ok=True)
    dq = bin_ / "dpkg-query"
    dq.write_text("#!/bin/sh\nprintf ' %s %s\\n' \"$DQ_FICHIER\" \"$DQ_MD5\"\n")
    dq.chmod(0o755)
    script = tmp_path / "m.sh"
    script.write_text(f"set -e\n{f}\nsbx_migrer_vhost {ancien} {nouveau} "
                      f"'{snip_ancien}' '{snip_nouveau}'\n")
    env = dict(os.environ, PATH=f"{bin_}:{os.environ['PATH']}",
               DQ_FICHIER=f"{racine}/etc/nginx/sites-available/{ancien}", DQ_MD5=md5_livre)
    return subprocess.run(["sh", str(script)], capture_output=True, text=True, env=env)


def _cadre(tmp_path: Path, ancien: str, contenu: str):
    sa = tmp_path / "etc/nginx/sites-available"; sa.mkdir(parents=True)
    (tmp_path / "etc/nginx/sites-enabled").mkdir(parents=True)
    (tmp_path / "etc/nginx/snippets/exposure").mkdir(parents=True)
    (sa / ancien).write_text(contenu)
    return sa


def test_ancien_vhost_retouche_archive_et_fichier_livre_intact(tmp_path):
    for i, (chemin, ancien, nouveau) in enumerate(MIGRATIONS):
        t = tmp_path / str(i); t.mkdir()
        sa = _cadre(t, ancien, "retouche de l'admin\ninclude /etc/nginx/snippets/exposure/x.gk2.secubox.in.conf;\n")
        (sa / nouveau).write_text("livre")
        livre = hashlib.md5(b"contenu d'origine").hexdigest()
        r = _lancer(t, chemin, ancien, nouveau, livre)
        assert r.returncode == 1, r.stderr      # 1 = l'ancien n'était pas activé
        assert (sa / nouveau).read_text() == "livre"          # jamais écrasé
        assert not (sa / ancien).exists()
        arch = list((t / "var/backups/nginx").glob(ancien + ".*"))
        assert len(arch) == 1
        assert stat.S_IMODE(arch[0].stat().st_mode) == 0o600
        assert "gk2.secubox.in.conf" in arch[0].read_text()
        assert "archiv" in r.stderr


def test_ancien_vhost_non_retouche_est_retire_sans_archive(tmp_path):
    for i, (chemin, ancien, nouveau) in enumerate(MIGRATIONS):
        t = tmp_path / str(i); t.mkdir()
        sa = _cadre(t, ancien, "contenu d'origine")
        (sa / nouveau).write_text("livre")
        r = _lancer(t, chemin, ancien, nouveau, hashlib.md5(b"contenu d'origine").hexdigest())
        assert r.returncode == 1, r.stderr
        assert not (sa / ancien).exists() and (sa / nouveau).read_text() == "livre"
        assert not (t / "var/backups/nginx").exists()


def test_lien_et_filtre_migres_et_idempotence(tmp_path):
    for i, (chemin, ancien, nouveau) in enumerate(MIGRATIONS):
        t = tmp_path / str(i); t.mkdir()
        sa = _cadre(t, ancien, "x")
        (t / "etc/nginx/sites-enabled" / ancien).symlink_to(sa / ancien)
        (t / "etc/nginx/snippets/exposure/vieux.conf").write_text("allow 1.2.3.4;\n")
        r = _lancer(t, chemin, ancien, nouveau, "", "vieux.conf", "neuf.conf")
        assert r.returncode == 0, r.stderr                      # 0 = ancien actif
        assert not os.path.lexists(t / "etc/nginx/sites-enabled" / ancien)
        assert (t / "etc/nginx/snippets/exposure/neuf.conf").read_text() == "allow 1.2.3.4;\n"
        r = _lancer(t, chemin, ancien, nouveau, "", "vieux.conf", "neuf.conf")
        assert r.returncode == 1                                # rien à migrer
