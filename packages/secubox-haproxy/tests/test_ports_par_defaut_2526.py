# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""haproxyctl generate sur une box NEUVE (ref #2526) : sans clés de port dans haproxy.toml, le cfg doit porter les ports par défaut.

`$(grep … | cut … | tr -d ' ' || echo "80")` : le `||` s'applique à `tr`, qui réussit toujours. Clé absente => valeur vide =>
`bind *:` et « missing port specification » (constaté sur une RPi400 fraîchement installée : aucun frontal)."""
import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest

CTL = Path(__file__).resolve().parents[1] / "sbin" / "haproxyctl"

TOML_BOX_NEUVE = """\
mode = "native"

[vhosts.hall]
domain = "hall.exemple.test"
backend = "nginx_vhosts"
enabled = true
ssl = true
"""


def _generer(tmp_path, toml_texte):
    if not shutil.which("bash"):
        pytest.skip("bash absent")
    for d in ("conf", "cfg", "cfgd", "bin"):
        (tmp_path / d).mkdir()
    (tmp_path / "conf" / "haproxy.toml").write_text(toml_texte, encoding="utf-8")
    faux = tmp_path / "bin" / "haproxy"
    faux.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    faux.chmod(0o755)
    env = dict(os.environ)
    env.update(PATH=f"{tmp_path / 'bin'}{os.pathsep}{env.get('PATH', '')}",
               SECUBOX_HAPROXY_CONF=str(tmp_path / "conf" / "haproxy.toml"),
               SECUBOX_HAPROXY_CONFIG_DIR=str(tmp_path / "cfg"),
               HAPROXY_DATA_PATH=str(tmp_path / "data"),
               HAPROXY_EXTRA_CFG_DIR=str(tmp_path / "cfgd"))
    p = subprocess.run(["bash", str(CTL), "generate"], env=env, capture_output=True, text=True, timeout=120)
    assert p.returncode == 0, f"generate a échoué :\n{p.stdout}\n{p.stderr}"
    return (tmp_path / "cfg" / "haproxy.cfg").read_text(encoding="utf-8")


def test_aucun_bind_sans_port_sur_une_box_neuve(tmp_path):
    cfg = _generer(tmp_path, TOML_BOX_NEUVE)
    sans_port = [l.strip() for l in cfg.splitlines() if re.match(r"\s*bind\s+\*:(\s|$)", l)]
    assert sans_port == [], f"bind sans port : {sans_port}"


def test_ports_par_defaut_80_443_8404(tmp_path):
    cfg = _generer(tmp_path, TOML_BOX_NEUVE)
    assert re.search(r"^\s*bind \*:80\b", cfg, re.M)
    assert re.search(r"^\s*bind \*:443 ssl", cfg, re.M)
    assert re.search(r"^\s*bind \*:8404\b", cfg, re.M)


def test_port_explicite_inchange(tmp_path):
    cfg = _generer(tmp_path, 'http_port = 8081\nhttps_port = 8443\nstats_port = 9000\n' + TOML_BOX_NEUVE)
    assert re.search(r"^\s*bind \*:8081\b", cfg, re.M)
    assert re.search(r"^\s*bind \*:8443 ssl", cfg, re.M)
    assert re.search(r"^\s*bind \*:9000\b", cfg, re.M)


def test_toml_vide_aussi(tmp_path):
    cfg = _generer(tmp_path, "")
    assert not re.search(r"^\s*bind\s+\*:(\s|$)", cfg, re.M)
