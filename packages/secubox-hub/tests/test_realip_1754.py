# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""nginx ne croit X-Forwarded-For que des adresses propres de la box (#1754)."""
import os
import re
import subprocess
from pathlib import Path

HUB = Path(__file__).resolve().parents[1]
SCRIPT = HUB / "sbin" / "secubox-realip"
GEO = (HUB / "nginx" / "secubox-lan-geo.conf").read_text()


def _lance(tmp_path, adresses, *args):
    cible = tmp_path / "real-ip.conf"
    env = {**os.environ, "SECUBOX_REALIP_ADDRS": adresses, "SECUBOX_REALIP_CIBLE": str(cible),
           "SECUBOX_REALIP_NORELOAD": "1"}
    r = subprocess.run([str(SCRIPT), *args], env=env, capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    return r.stdout, cible


def test_une_directive_par_adresse_propre(tmp_path):
    _, cible = _lance(tmp_path, "192.168.1.200 10.100.0.1 127.0.0.1")
    lignes = [l for l in cible.read_text().splitlines() if l.startswith("set_real_ip_from")]
    assert lignes == ["set_real_ip_from 10.100.0.1;", "set_real_ip_from 127.0.0.1;",
                      "set_real_ip_from 192.168.1.200;"]
    assert "/" not in "".join(lignes)                       # jamais une plage


def test_adresse_invalide_ignoree(tmp_path):
    _, cible = _lance(tmp_path, "192.168.1.9 pas-une-ip 10.0.0.0/8")
    assert [l for l in cible.read_text().splitlines() if l.startswith("set_real_ip_from")] == \
        ["set_real_ip_from 192.168.1.9;"]


def test_idempotent(tmp_path):
    _, cible = _lance(tmp_path, "192.168.1.9")
    avant = cible.stat().st_mtime_ns
    _lance(tmp_path, "192.168.1.9")
    assert cible.stat().st_mtime_ns == avant                # inchangé : pas de réécriture ni de reload


def test_etat_n_ecrit_rien(tmp_path):
    sortie, cible = _lance(tmp_path, "192.168.1.9", "--etat")
    assert "set_real_ip_from 192.168.1.9;" in sortie and not cible.exists()


def test_plus_aucune_plage_de_confiance_dans_la_conf_livree():
    directives = re.findall(r"^set_real_ip_from\s+(\S+);", GEO, re.M)
    assert directives == ["127.0.0.1"]                      # avant : 192.168.1.0/24, 10.100.0.0/24…
    assert "real_ip_header X-Forwarded-For;" in GEO


def test_verdict_lan_inchange():
    # Le geo décide sur l'adresse finale : les postes du LAN restent « LAN ».
    for plage in ("192.168.1.0/24", "10.100.0.0/24", "127.0.0.0/8"):
        assert re.search(rf"^\s*{re.escape(plage)}\s+1;", GEO, re.M), plage
