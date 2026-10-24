# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""#3117 : le vhost du Hall est livré sous un nom et des server_name neutres.

Le corps du vhost garde des références fonctionnelles au parc de gk2 (CSP,
en-têtes Host des relais) : hors périmètre de #3117, seuls le server_name, le
nom du fichier installé et l'en-tête du fichier sont vérifiés ici."""
import re
from pathlib import Path

PKG = Path(__file__).resolve().parent.parent
VHOST = (PKG / "nginx" / "hall.vhost.conf").read_text(encoding="utf-8")
RULES = (PKG / "debian" / "rules").read_text(encoding="utf-8")
POSTINST = (PKG / "debian" / "postinst").read_text(encoding="utf-8")


def test_server_name_sans_gk2():
    noms = re.findall(r"^\s*server_name\s+([^;]+);", VHOST, re.M)
    assert noms
    for n in noms:
        assert "gk2" not in n, n
    assert "server_name hall.localhost hall.*;" in VHOST


def test_entete_neutre():
    assert "gk2" not in "\n".join(VHOST.splitlines()[:10])


def test_installe_sous_hall_conf():
    assert "sites-available/hall.conf" in RULES
    assert "sites-available/hall.gk2.net.conf" not in RULES


def test_postinst_active_hall_conf_et_migre_le_lien():
    assert "ln -s ../sites-available/hall.conf" in POSTINST
    assert "sites-enabled/hall.gk2.net.conf" in POSTINST  # retrait de l'ancien lien


def test_maintscript_deplace_l_ancien_conffile():
    m = (PKG / "debian" / "secubox-webos.maintscript").read_text(encoding="utf-8")
    assert ("mv_conffile /etc/nginx/sites-available/hall.gk2.net.conf "
            "/etc/nginx/sites-available/hall.conf") in m


# ── Le Hall reste activé à travers la montée (preinst + postinst) ──────────
import os
import shutil
import subprocess

import pytest

PREINST = PKG / "debian" / "preinst"


def _chroot_script(texte: str, racine: Path) -> str:
    return (texte.replace("/etc/nginx", f"{racine}/etc/nginx")
                 .replace("/var/lib/secubox", f"{racine}/var/lib/secubox"))


def _bloc_postinst() -> str:
    deb = POSTINST.index("_hall_actif=0")
    fin = POSTINST.index("    # Filet :", deb)
    return POSTINST[deb:fin]


def _monter(tmp_path: Path):
    sa = tmp_path / "etc/nginx/sites-available"
    se = tmp_path / "etc/nginx/sites-enabled"
    sa.mkdir(parents=True); se.mkdir(parents=True)
    (sa / "hall.gk2.net.conf").write_text("ancien")
    (se / "hall.gk2.net.conf").symlink_to("../sites-available/hall.gk2.net.conf")
    return sa, se


def _preinst(tmp_path: Path, *args: str):
    src = tmp_path / "preinst.sh"
    src.write_text(_chroot_script(PREINST.read_text(encoding="utf-8"), tmp_path)
                   .replace("#DEBHELPER#", ""))
    return subprocess.run(["sh", str(src), *args], capture_output=True, text=True)


def _postinst(tmp_path: Path, ancienne: str):
    src = tmp_path / "postinst.sh"
    src.write_text("set -e\n" + _chroot_script(_bloc_postinst(), tmp_path))
    return subprocess.run(["sh", str(src), "configure", ancienne], capture_output=True, text=True)


@pytest.mark.skipif(shutil.which("dpkg") is None, reason="dpkg absent")
def test_la_montee_ne_laisse_aucun_lien_pendant_et_reactive_le_hall(tmp_path):
    sa, se = _monter(tmp_path)
    r = _preinst(tmp_path, "upgrade", "1.19.25-1~trixie1")
    assert r.returncode == 0, r.stderr
    # fenêtre du dépaquetage : l'ancien lien a disparu, aucun lien ne pend
    assert not os.path.lexists(se / "hall.gk2.net.conf")
    assert (tmp_path / "var/lib/secubox/webos/.hall-reactiver").exists()
    # dépaquetage : mv_conffile a renommé le fichier, dpkg pose le nouveau
    (sa / "hall.gk2.net.conf").unlink()
    (sa / "hall.conf").write_text("nouveau")
    r = _postinst(tmp_path, "1.19.25-1~trixie1")
    assert r.returncode == 0, r.stderr
    assert (se / "hall.conf").is_symlink() and (se / "hall.conf").exists()
    assert not (tmp_path / "var/lib/secubox/webos/.hall-reactiver").exists()


@pytest.mark.skipif(shutil.which("dpkg") is None, reason="dpkg absent")
def test_un_hall_desactive_a_la_main_le_reste(tmp_path):
    sa, se = _monter(tmp_path)
    (se / "hall.gk2.net.conf").unlink()           # désactivé par l'exploitant
    assert _preinst(tmp_path, "upgrade", "1.19.25-1~trixie1").returncode == 0
    assert not (tmp_path / "var/lib/secubox/webos/.hall-reactiver").exists()
    (sa / "hall.gk2.net.conf").unlink()
    (sa / "hall.conf").write_text("nouveau")
    assert _postinst(tmp_path, "1.19.25-1~trixie1").returncode == 0
    assert not os.path.lexists(se / "hall.conf")


@pytest.mark.skipif(shutil.which("dpkg") is None, reason="dpkg absent")
def test_le_preinst_ne_touche_rien_depuis_une_version_deja_migree(tmp_path):
    sa, se = _monter(tmp_path)
    (se / "hall.gk2.net.conf").unlink()
    (se / "hall.conf").symlink_to("../sites-available/hall.conf")
    assert _preinst(tmp_path, "upgrade", "1.19.26-1~trixie1").returncode == 0
    assert not (tmp_path / "var/lib/secubox/webos/.hall-reactiver").exists()
    assert os.path.lexists(se / "hall.conf")
