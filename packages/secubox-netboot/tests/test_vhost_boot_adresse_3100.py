# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3100/#3117 — le vhost de boot n'écoute plus sur l'adresse de gk2 : l'adresse LAN de la box est posée à l'activation."""
import subprocess
from pathlib import Path

ICI = Path(__file__).resolve().parents[1]
VHOST = ICI / "nginx" / "boot-vhost.conf"
SERVE = ICI / "sbin" / "secubox-netboot-serve"


def test_gabarit_sans_adresse_de_gk2():
    s = VHOST.read_text()
    assert "192.168.1.200" not in s
    assert "listen @ADRESSE_LAN@:8099;" in s


def test_plus_de_location_sbxboot_livree():
    assert not (ICI / "nginx" / "netboot-server.conf").exists()
    assert "netboot-server.conf" not in (ICI / "debian" / "rules").read_text()


def _adresse(env):
    """Appelle la seule fonction adresse_lan du script (sans rien activer)."""
    r = subprocess.run(["bash", "-c", f"source {SERVE} --bibliotheque; adresse_lan"],
                       capture_output=True, text=True, env=env)
    return r.returncode, r.stdout.strip()


def test_adresse_imposee_par_l_environnement():
    assert _adresse({"PATH": "/usr/bin:/bin", "SBX_NETBOOT_ADRESSE": "192.168.1.94"}) == (0, "192.168.1.94")


def test_adresse_publique_ou_invalide_refusee():
    for a in ("8.8.8.8", "127.0.0.1", "192.168.1.300", "1.2.3", "10.10.0.8"):
        rc, _ = _adresse({"PATH": "/usr/bin:/bin", "SBX_NETBOOT_ADRESSE": a})
        assert rc != 0, a


def _admise(a, explicite):
    r = subprocess.run(["bash", "-c", f"source {SERVE} --bibliotheque; adresse_admise {a} {explicite}"],
                       capture_output=True, text=True, env={"PATH": "/usr/bin:/bin"})
    return r.returncode == 0


def test_detectee_10_8_refusee_explicite_admise():
    assert _admise("192.168.1.200", 0) and _admise("172.20.0.5", 0)
    assert not _admise("10.20.3.4", 0)          # réseau du FAI ou d'immeuble possible : explicite exigé
    assert _admise("10.20.3.4", 1)
    assert not _admise("10.100.0.1", 1) and not _admise("10.0.3.1", 1) and not _admise("100.64.0.1", 0)


def test_lance_hors_source_avec_bibliotheque_ne_fait_rien():
    r = subprocess.run(["bash", str(SERVE), "--bibliotheque"], capture_output=True, text=True)
    assert r.returncode == 0 and r.stdout == ""


def test_racine_http_reservee_au_lan():
    """Le live et les images eMMC : LAN seulement, dans le gabarit même (l'ancien vhost le faisait par un snippet)."""
    s = VHOST.read_text()
    bloc = s[s.index("location / {"):]
    bloc = bloc[:bloc.index("}")]
    for ligne in ("allow 127.0.0.1;", "allow 10.0.0.0/8;", "allow 172.16.0.0/12;", "allow 192.168.0.0/16;", "deny all;"):
        assert ligne in bloc, ligne


def test_gabarit_sans_marqueur_dans_les_commentaires():
    s = VHOST.read_text()
    assert s.count("@ADRESSE_LAN@") == 1


def test_statut_lit_le_vhost_pose_et_non_nginx_T(tmp_path):
    """#3233 : sous ProtectSystem=strict (API), `nginx -T` échouait et le statut disait « no » alors que le vhost servait."""
    vhost = tmp_path / "secubox-netboot-boot.conf"
    vhost.write_text("server {\n    listen 192.168.1.200:8099;\n    root /srv/secubox/netboot/http;\n}\n")
    faux = tmp_path / "nginx"
    faux.write_text("#!/bin/sh\nexit 1\n")                       # nginx -T en échec, comme sous le bac à sable
    faux.chmod(0o755)
    env = {"PATH": f"{tmp_path}:/usr/bin:/bin", "SBX_NETBOOT_VHOST": str(vhost)}
    r = subprocess.run(["bash", "-c", f"source {SERVE} --bibliotheque; set -o pipefail; cmd_status"],
                       capture_output=True, text=True, env=env, timeout=60)
    assert '"nginx_sbxboot":"yes"' in r.stdout.replace(" ", ""), r.stdout
    vhost.unlink()
    r = subprocess.run(["bash", "-c", f"source {SERVE} --bibliotheque; set -o pipefail; cmd_status"],
                       capture_output=True, text=True, env=env, timeout=60)
    assert '"nginx_sbxboot":"no"' in r.stdout.replace(" ", ""), r.stdout
