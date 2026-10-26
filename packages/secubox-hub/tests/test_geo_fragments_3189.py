# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3189 — la géo `$lan_client` accepte des fragments (`/etc/nginx/secubox-lan-geo.d/*.conf`) : le LAN du mode routeur
de netmodes (`<cidr> 1;`) devient de confiance comme le LAN de la Freebox. Le postinst crée le dossier."""
import re
import shutil
import subprocess
from pathlib import Path

import pytest

PKG = Path(__file__).resolve().parents[1]
GEO = PKG / "nginx" / "secubox-lan-geo.conf"
POSTINST = PKG / "debian" / "postinst"
INCLUDE = "include /etc/nginx/secubox-lan-geo.d/netmodes-lan.conf;"


def _bloc_geo() -> str:
    m = re.search(r"geo \$lan_client \{(.*?)\n\}", GEO.read_text(encoding="utf-8"), re.S)
    assert m, "bloc geo $lan_client introuvable"
    return m.group(1)


def test_include_dans_le_bloc_geo_lan_client():
    lignes = [x.strip() for x in _bloc_geo().splitlines() if not x.strip().startswith("#")]
    assert INCLUDE in lignes


def test_include_apres_les_plages_fixes():
    lignes = [x.strip() for x in _bloc_geo().splitlines() if x.strip() and not x.strip().startswith("#")]
    assert lignes[-1] == INCLUDE


def test_postinst_cree_le_dossier_des_fragments():
    txt = POSTINST.read_text(encoding="utf-8")
    assert re.search(r"install -d -o root -g root -m 0?755 /etc/nginx/secubox-lan-geo\.d", txt)


def test_postinst_cree_le_fragment_vide_car_geo_n_expanse_pas_de_joker():
    assert "/etc/nginx/secubox-lan-geo.d/netmodes-lan.conf" in POSTINST.read_text(encoding="utf-8")


def test_nginx_t_accepte_un_fragment(tmp_path):
    nginx = shutil.which("nginx") or ("/usr/sbin/nginx" if Path("/usr/sbin/nginx").exists() else None)
    if not nginx:
        pytest.skip("nginx absent")
    frag = tmp_path / "geo.d"
    frag.mkdir()
    (frag / "netmodes-lan.conf").write_text("192.168.42.0/24 1;\n")
    geo = tmp_path / "geo.conf"
    geo.write_text("geo $lan_client {\n    default 0;\n" + _bloc_geo().replace(
        "/etc/nginx/secubox-lan-geo.d", str(frag)).split("default        0;", 1)[-1] + "\n}\n")
    conf = tmp_path / "nginx.conf"
    conf.write_text(f"pid {tmp_path}/n.pid;\nerror_log {tmp_path}/e.log;\nevents {{}}\n"
                    f"http {{\n  access_log off;\n  include {geo};\n}}\n")
    r = subprocess.run([nginx, "-t", "-c", str(conf), "-p", str(tmp_path)],
                       capture_output=True, text=True, timeout=20)
    if r.returncode != 0 and "Permission denied" in r.stderr:
        pytest.skip("nginx -t ne peut pas tourner ici : " + r.stderr.strip()[:200])
    assert r.returncode == 0, r.stderr
