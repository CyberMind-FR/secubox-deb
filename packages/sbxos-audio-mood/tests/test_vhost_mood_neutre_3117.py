# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3117 : le vhost de mood est livré sans les noms de gk2, migration sûre."""
from pathlib import Path

PKG = Path(__file__).resolve().parent.parent
VHOST = (PKG / "nginx" / "mood.vhost.conf").read_text(encoding="utf-8")
RULES = (PKG / "debian" / "rules").read_text(encoding="utf-8")
POSTINST = (PKG / "debian" / "postinst").read_text(encoding="utf-8")
ANCIEN, NOUVEAU = "mood.gk2.secubox.in.conf", "mood.conf"


def test_server_name_generique():
    assert "server_name mood.*;" in VHOST
    assert "include /etc/nginx/snippets/exposure/mood.conf;" in VHOST


def test_nom_installe_neutre():
    assert "sites-available/mood.conf" in RULES
    assert "gk2" not in "".join(l for l in RULES.splitlines() if "sites-available" in l)


def test_postinst_migre_avant_de_semer_le_filtre():
    assert "HOTE=mood\n" in POSTINST
    appel = POSTINST.index("sbx_migrer_vhost mood.gk2.secubox.in.conf mood.conf")
    assert appel < POSTINST.index('if [ ! -f "/etc/nginx/snippets/exposure/$HOTE.conf" ]')


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


def _lancer(tmp_path: Path, ancien: str, nouveau: str, md5_livre: str,
            snip_ancien: str = "", snip_nouveau: str = ""):
    racine = tmp_path
    f = (_fonction(PKG / "debian" / "postinst").replace("/etc/nginx", f"{racine}/etc/nginx")
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


def _cadre(tmp_path: Path, contenu: str):
    sa = tmp_path / "etc/nginx/sites-available"; sa.mkdir(parents=True)
    (tmp_path / "etc/nginx/sites-enabled").mkdir(parents=True)
    (tmp_path / "etc/nginx/snippets/exposure").mkdir(parents=True)
    (sa / ANCIEN).write_text(contenu)
    return sa


def test_ancien_vhost_retouche_archive_et_fichier_livre_intact(tmp_path):
    sa = _cadre(tmp_path, "retouche de l'admin\nserver_name x.gk2.secubox.in;\n")
    (sa / NOUVEAU).write_text("livre")
    r = _lancer(tmp_path, ANCIEN, NOUVEAU, hashlib.md5(b"contenu d'origine").hexdigest())
    assert r.returncode == 1, r.stderr      # 1 = l'ancien n'était pas activé
    assert (sa / NOUVEAU).read_text() == "livre"          # jamais écrasé
    assert not (sa / ANCIEN).exists()
    arch = list((tmp_path / "var/backups/nginx").glob(ANCIEN + ".*"))
    assert len(arch) == 1
    assert stat.S_IMODE(arch[0].stat().st_mode) == 0o600
    assert "gk2" in arch[0].read_text()
    assert "archiv" in r.stderr


def test_ancien_vhost_non_retouche_est_retire_sans_archive(tmp_path):
    sa = _cadre(tmp_path, "contenu d'origine")
    (sa / NOUVEAU).write_text("livre")
    r = _lancer(tmp_path, ANCIEN, NOUVEAU, hashlib.md5(b"contenu d'origine").hexdigest())
    assert r.returncode == 1, r.stderr
    assert not (sa / ANCIEN).exists() and (sa / NOUVEAU).read_text() == "livre"
    assert not (tmp_path / "var/backups/nginx").exists()


def test_lien_et_filtre_migres_et_idempotence(tmp_path):
    sa = _cadre(tmp_path, "x")
    (tmp_path / "etc/nginx/sites-enabled" / ANCIEN).symlink_to(sa / ANCIEN)
    (tmp_path / "etc/nginx/snippets/exposure/vieux.conf").write_text("allow 1.2.3.4;\n")
    r = _lancer(tmp_path, ANCIEN, NOUVEAU, "", "vieux.conf", "neuf.conf")
    assert r.returncode == 0, r.stderr                      # 0 = ancien actif
    assert not os.path.lexists(tmp_path / "etc/nginx/sites-enabled" / ANCIEN)
    assert (tmp_path / "etc/nginx/snippets/exposure/neuf.conf").read_text() == "allow 1.2.3.4;\n"
    r = _lancer(tmp_path, ANCIEN, NOUVEAU, "", "vieux.conf", "neuf.conf")
    assert r.returncode == 1                                # rien à migrer


def test_lien_migre_jamais_retire_sur_echec_de_nginx_t():
    t = (PKG / "debian" / "postinst").read_text(encoding="utf-8")
    assert re.search(r'elif \[ "\$\{?MIGRE\}?" = 1 \]', t), "lien migré retiré sur échec de nginx -t"


def test_lien_pose_a_la_main_sous_un_autre_nom_retire(tmp_path):
    sa = _cadre(tmp_path, "x")
    autre = tmp_path / "etc/nginx/sites-enabled/pose-a-la-main"
    autre.symlink_to("../sites-available/" + ANCIEN)
    voisin = tmp_path / "etc/nginx/sites-enabled/voisin.conf"
    (sa / "voisin.conf").write_text("y")
    voisin.symlink_to("../sites-available/voisin.conf")
    r = _lancer(tmp_path, ANCIEN, NOUVEAU, "")
    assert r.returncode == 0, r.stderr          # compté comme activé
    assert not os.path.lexists(autre)           # ne pend pas
    assert os.path.lexists(voisin)              # les autres liens sont intacts
