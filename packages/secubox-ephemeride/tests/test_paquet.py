# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""Paquet secubox-ephemeride : unité durcie sans privilège, socket 0660, route, données, configuration livrée."""
import json
import re
import tomllib
from pathlib import Path

from api import config

PKG = Path(__file__).resolve().parents[1]
UNITE = (PKG / "systemd" / "secubox-ephemeride.service").read_text()
RULES = (PKG / "debian" / "rules").read_text()
POSTINST = (PKG / "debian" / "postinst").read_text()


def test_unite_sans_privilege_et_durcie():
    assert "User=secubox-ephemeride" in UNITE and "User=root" not in UNITE
    for d in ("NoNewPrivileges=yes", "ProtectSystem=strict", "ProtectHome=yes", "PrivateTmp=yes", "ProtectKernelTunables=yes",
              "ProtectControlGroups=yes", "RestrictSUIDSGID=yes", "LockPersonality=yes", "UMask=0027", "CapabilityBoundingSet="):
        assert re.search(rf"(?m)^{re.escape(d)}\s*$", UNITE), d
    assert "ReadWritePaths=/run/secubox /var/lib/secubox/ephemeride" in UNITE


def test_socket_unix_0660_et_nettoyage_en_racine():
    assert "--uds /run/secubox/ephemeride.sock" in UNITE and "--port" not in UNITE
    assert "chmod 660 /run/secubox/ephemeride.sock" in UNITE
    assert "ExecStartPre=+/bin/rm -f /run/secubox/ephemeride.sock" in UNITE
    assert "RuntimeDirectory=secubox" not in UNITE


def test_rules_installe_code_donnees_config_route_et_unite():
    for s in ("api/*.py", "saints.json", "ephemeride.toml", "secubox-routes.d/ephemeride.conf", "secubox-ephemeride.service"):
        assert s in RULES, s


def test_postinst_ne_remplace_jamais_la_configuration_de_l_operateur():
    assert re.search(r"if \[ ! -e /etc/secubox/ephemeride.toml \]", POSTINST)
    assert "try-restart" in POSTINST and "adduser" in POSTINST


def test_la_configuration_livree_est_lue_par_le_module_sans_erreur():
    brut = tomllib.loads((PKG / "conf" / "ephemeride.toml").read_text())["ephemeride"]
    assert brut["enabled"] is True and brut["weather"]["provider"] == "auto"
    c = config.charger(PKG / "conf" / "ephemeride.toml", defaut=PKG / "absent.toml")
    assert c.enabled and c.meteo.ttl_s == 900 and c.air.ttl_s == 1800 and c.lieu().approximatif is True


def test_les_donnees_de_saints_sont_completes_et_bien_formees():
    d = json.loads((PKG / "data" / "saints.json").read_text())["saints"]
    assert len(d) == 366
    for jour, saints in d.items():
        assert re.fullmatch(r"\d\d-\d\d", jour) and saints
        for s in saints:
            assert s["nom"].strip() and isinstance(s["description"], str)


def test_la_route_nginx_vise_la_socket_du_module():
    conf = (PKG / "nginx" / "ephemeride.conf").read_text()
    assert "proxy_pass http://unix:/run/secubox/ephemeride.sock:/;" in conf and "/api/v1/ephemeride/" in conf
