# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""SecuBox-Deb :: haproxyctl frontal — la box derrière HAProxy + sbxwaf (#1841).

On EXÉCUTE `haproxyctl frontal` sur une arborescence temporaire qui reproduit
gk3 avant bascule : nginx seul sur 80/443 (site « secubox »), un haproxy.toml
sans réglages généraux, un frontal gitea-ssh posé à la main dans haproxy.cfg.
nginx, systemctl, ss, curl, haproxy et secubox-domaine sont des doublures qui
consignent leurs appels.
"""
import os
import shutil
import subprocess
from pathlib import Path

import pytest

CTL = Path(__file__).resolve().parents[1] / "sbin" / "haproxyctl"

TOML_GK3 = """\
[vhosts.identity_gk3_secubox_in]
domain = "identity.gk3.secubox.in"
backend = "nginx_vhosts"
ssl = true
enabled = true
"""

CFG_GK3 = """\
global
    daemon

defaults
    mode http

frontend gitea-ssh
    bind *:2222
    mode tcp
    default_backend gitea_ssh

backend gitea_ssh
    mode tcp
    server gitea_lxc 10.100.0.40:2222 check
"""


def _doublure(bin_dir: Path, nom: str, corps: str) -> None:
    f = bin_dir / nom
    f.write_text("#!/bin/bash\n" + corps, encoding="utf-8")
    f.chmod(0o755)


@pytest.fixture
def box(tmp_path):
    if not shutil.which("bash"):
        pytest.skip("bash absent")
    d = {k: tmp_path / k for k in ("conf", "cfg", "cfgd", "data", "nginx", "tls", "bin")}
    for p in d.values():
        p.mkdir()
    (d["nginx"] / "sites-available").mkdir()
    (d["nginx"] / "sites-enabled").mkdir()
    site = d["nginx"] / "sites-available" / "secubox"
    site.write_text("server { listen 443 ssl; server_name _; }\n", encoding="utf-8")
    (d["nginx"] / "sites-enabled" / "secubox").symlink_to(site)
    (d["conf"] / "haproxy.toml").write_text(TOML_GK3, encoding="utf-8")
    (d["cfg"] / "haproxy.cfg").write_text(CFG_GK3, encoding="utf-8")
    (d["tls"] / "cert.pem").write_text("-----CERT-----\n", encoding="utf-8")
    (d["tls"] / "key.pem").write_text("-----KEY-----\n", encoding="utf-8")
    defaut = tmp_path / "secubox.defaults"
    defaut.write_text('SECUBOX_HOSTNAME="gk3"\nSECUBOX_DOMAIN_SUFFIX="secubox.in"\n', encoding="utf-8")
    journal = tmp_path / "appels.log"
    b = d["bin"]
    _doublure(b, "haproxy", "exit 0\n")
    _doublure(b, "secubox-domaine", 'echo "${DOUBLURE_DOMAINE:-gk3.secubox.in}"\n')
    _doublure(b, "ss", 'echo "LISTEN 0 4096 ${DOUBLURE_SS:-127.0.0.1:8085} 0.0.0.0:*"\n')
    _doublure(b, "nginx", f'echo "nginx $*" >> "{journal}"; exit 0\n')
    _doublure(b, "systemctl", f'echo "systemctl $*" >> "{journal}"; exit 0\n')
    _doublure(b, "curl", 'printf "%s" "${DOUBLURE_CODE:-200}"\n')
    _doublure(b, "sleep", "exit 0\n")
    env = dict(os.environ)
    env.update(
        PATH=f"{b}{os.pathsep}{env.get('PATH', '')}",
        SECUBOX_HAPROXY_CONF=str(d["conf"] / "haproxy.toml"),
        SECUBOX_HAPROXY_CONFIG_DIR=str(d["cfg"]),
        HAPROXY_DATA_PATH=str(d["data"]),
        HAPROXY_EXTRA_CFG_DIR=str(d["cfgd"]),
        SECUBOX_NGINX_DIR=str(d["nginx"]),
        SECUBOX_TLS_DIR=str(d["tls"]),
        SECUBOX_DEFAULTS_FILE=str(defaut),
    )

    def lance(*args, **surcharges):
        e = dict(env, **surcharges)
        return subprocess.run(["bash", str(CTL), "frontal", *args], env=e,
                              capture_output=True, text=True, timeout=120)

    def appels():
        return journal.read_text(encoding="utf-8").splitlines() if journal.exists() else []

    return d, defaut, lance, appels


def test_bascule_complete_depuis_un_etat_gk3(box):
    d, _, lance, appels = box
    p = lance()
    assert p.returncode == 0, p.stdout + p.stderr

    toml = (d["conf"] / "haproxy.toml").read_text()
    assert toml.startswith("[main]") and 'waf_backend_port = 8085' in toml
    assert "[vhosts.identity_gk3_secubox_in]" in toml          # rien de perdu

    pem = d["data"] / "certs" / "000-defaut.pem"
    assert pem.read_text() == "-----CERT-----\n-----KEY-----\n"
    assert oct(pem.stat().st_mode & 0o777) == "0o600"

    cfgd = (d["cfgd"] / "20-gitea-ssh.cfg").read_text()
    assert "frontend gitea-ssh" in cfgd and "backend gitea_ssh" in cfgd
    cfg = (d["cfg"] / "haproxy.cfg").read_text()
    assert "frontend https-in" in cfg and cfg.count("frontend gitea-ssh") == 1

    lien = d["nginx"] / "sites-enabled" / "secubox"
    assert os.readlink(lien) == str(d["nginx"] / "sites-available" / "secubox-frontal")
    assert "listen" not in (d["nginx"] / "sites-available" / "secubox-frontal").read_text()

    a = appels()
    assert a.index("systemctl reload nginx") < a.index("systemctl restart haproxy")
    assert lance("--etat").returncode == 0


def test_identite_incoherente_refusee_sans_rien_toucher(box):
    d, defaut, lance, appels = box
    defaut.write_text('SECUBOX_HOSTNAME="gk2"\nSECUBOX_DOMAIN_SUFFIX="secubox.in"\n')
    p = lance()
    assert p.returncode != 0 and "gk2.secubox.in" in p.stderr
    assert (d["conf"] / "haproxy.toml").read_text() == TOML_GK3
    assert (d["cfg"] / "haproxy.cfg").read_text() == CFG_GK3
    assert os.readlink(d["nginx"] / "sites-enabled" / "secubox").endswith("/secubox")
    assert appels() == []


def test_sans_sbxwaf_refuse(box):
    d, _, lance, appels = box
    p = lance(DOUBLURE_SS="0.0.0.0:22")
    assert p.returncode != 0 and "sbxwaf" in p.stderr
    assert (d["cfg"] / "haproxy.cfg").read_text() == CFG_GK3
    assert appels() == []


def test_box_muette_apres_bascule_retour_arriere(box):
    d, _, lance, appels = box
    p = lance(DOUBLURE_CODE="000")
    assert p.returncode != 0 and "retour arriere" in p.stderr
    assert os.readlink(d["nginx"] / "sites-enabled" / "secubox") == str(d["nginx"] / "sites-available" / "secubox")
    assert (d["cfg"] / "haproxy.cfg").read_text() == CFG_GK3
    assert "systemctl reload haproxy" in appels()


def test_idempotent(box):
    d, _, lance, appels = box
    assert lance().returncode == 0
    n = len(appels())
    p = lance()
    assert p.returncode == 0 and "deja actif" in (p.stdout + p.stderr)
    assert len(appels()) == n


def test_admin_par_ip_sur_le_lan_seulement(box):
    d, _, lance, _ = box
    p = lance("--admin-lan", "192.168.1.9")
    assert p.returncode == 0, p.stdout + p.stderr
    lan = (d["cfgd"] / "10-webui-lan.cfg").read_text()
    assert "bind 192.168.1.9:9443 ssl crt" in lan and "*:9443" not in lan
    assert "default_backend webui_direct" in lan
    assert "frontend webui-lan" in (d["cfg"] / "haproxy.cfg").read_text()


@pytest.mark.parametrize("ip", ["0.0.0.0", "82.67.100.75", "192.168.1.9;rm", ""])
def test_admin_lan_refuse_une_adresse_publique_ou_douteuse(box, ip):
    d, _, lance, appels = box
    p = lance("--admin-lan", ip)
    assert p.returncode != 0
    assert not (d["cfgd"] / "10-webui-lan.cfg").exists() and appels() == []
