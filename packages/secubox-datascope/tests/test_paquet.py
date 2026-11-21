# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3853 — squelette du paquet DataScope : unités, route, confinement, postinst, API, configuration."""
import re
import sys
from pathlib import Path

from fastapi.testclient import TestClient

RACINE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RACINE))

from api import main  # noqa: E402
from secubox_datascope import config  # noqa: E402


def _lire(rel):
    return (RACINE / rel).read_text(encoding="utf-8")


def _lignes(rel):
    return {ligne.strip() for ligne in _lire(rel).splitlines()}


def test_unite_api_durcie():
    u = _lire("debian/secubox-datascope.service")
    for attendu in ("--uds /run/secubox/datascope.sock", "User=secubox-datascope", "Group=secubox",
                    "RestrictAddressFamilies=AF_UNIX", "IPAddressDeny=any", "MemoryMax=128M",
                    "AppArmorProfile=-secubox-datascope",
                    "ReadWritePaths=/run/secubox -/data/secubox-datascope -/var/cache/secubox/datascope"):
        assert attendu in u, attendu
    assert "RuntimeDirectory" not in u
    assert "ListenStream" not in u and "--port" not in u


def test_collecteur_et_minuterie():
    c = _lignes("debian/secubox-datascope-collect.service")
    for attendu in ("Type=oneshot", "Nice=10", "CPUQuota=25%", "IOSchedulingClass=idle", "MemoryMax=128M",
                    "User=secubox-datascope", "Group=secubox", "StateDirectory=secubox-datascope",
                    "AppArmorProfile=-secubox-datascope", "RestrictAddressFamilies=AF_UNIX",
                    "IPAddressDeny=any", "WorkingDirectory=/usr/lib/secubox/datascope",
                    "ExecStart=/usr/bin/python3 -m secubox_datascope.collecte"):
        assert attendu in c, attendu
    assert any(x.startswith("ReadWritePaths=") and "-/data/secubox-datascope" in x
               and "-/var/cache/secubox/datascope" in x for x in c)
    t = _lignes("debian/secubox-datascope-collect.timer")
    assert "OnCalendar=*:*:00/60" in t or "OnUnitActiveSec=60" in t or "OnUnitActiveSec=60s" in t
    assert "RandomizedDelaySec=15" in t or "RandomizedDelaySec=15s" in t


def test_route_nginx_unique():
    n = _lire("nginx/datascope.conf")
    assert len(re.findall(r"^\s*location\s", n, re.M)) == 1
    assert "location /api/v1/datascope/" in n
    assert "unix:/run/secubox/datascope.sock" in n
    assert "alias" not in n and "error_page" not in n


def test_rules_installe_route_et_page():
    r = _lire("debian/rules")
    assert "/etc/nginx/secubox-routes.d/" in r
    assert "/usr/share/secubox/www/datascope/" in r


def test_postinst():
    p = _lire("debian/postinst")
    assert "adduser" in p and "secubox-datascope" in p
    assert "mountpoint -q /data" in p
    assert "0750" in p
    assert "systemctl enable --now secubox-datascope.service" in p
    assert "systemctl enable --now secubox-datascope-collect.timer" in p
    assert p.index("apparmor_parser") < p.index("systemctl enable --now")


def test_control():
    c = _lire("debian/control")
    assert "Standards-Version: 4.6.2" in c
    assert "Architecture: all" in c
    assert "python3-fastapi" in c and "python3-uvicorn" in c and "secubox-core" in c
    assert _lire("debian/compat").strip() == "13"
    assert _lire("debian/changelog").startswith("secubox-datascope (0.1.0-1~trixie1) trixie;")


def test_health_sans_jeton():
    r = TestClient(main.app).get("/api/v1/datascope/health")
    assert r.status_code == 200
    assert r.json() == {"status": "ok", "module": "datascope", "version": "0.1.0"}


def _gardes(chemin):
    for r in main.app.routes:
        if getattr(r, "path", None) == chemin:
            return {d.call.__name__ for d in r.dependant.dependencies}
    raise AssertionError(chemin)


def test_status_garde_et_contenu(tmp_path, monkeypatch):
    assert "require_lecture" in _gardes("/api/v1/datascope/status")
    monkeypatch.setattr(main, "CFG", config.Config(
        base=tmp_path / "absente.db", cache=tmp_path, nac_db=tmp_path / "n", netstats=tmp_path / "s",
        modules=tmp_path / "m"))
    d = main.status()
    assert d == {"module": "datascope", "base": "absente", "derniere_passe": None}


def test_config_environnement_toml_defauts(tmp_path, monkeypatch):
    for k in ("DB", "CACHE", "NAC_DB", "NETSTATS", "MODULES"):
        monkeypatch.delenv("SECUBOX_DATASCOPE_" + k, raising=False)
    d = config.charger(tmp_path / "absent.toml")
    assert d.base == Path("/var/lib/secubox-datascope/datascope.db")
    assert d.cache == Path("/var/cache/secubox/datascope")
    assert d.nac_db == Path("/var/lib/secubox/nac/devices.db")
    assert d.netstats == Path("/var/lib/secubox/hub/netstats.json")
    assert d.modules == Path("/var/cache/secubox/health/modules.json")
    assert d.modules_perime_s == 300
    f = tmp_path / "d.toml"
    f.write_text('[stockage]\nbase = "/data/secubox-datascope/datascope.db"\n[sources]\nmodules_perime_s = 120\n')
    t = config.charger(f)
    assert t.base == Path("/data/secubox-datascope/datascope.db") and t.modules_perime_s == 120
    monkeypatch.setenv("SECUBOX_DATASCOPE_DB", str(tmp_path / "env.db"))
    assert config.charger(f).base == tmp_path / "env.db"
    f.write_text("pas du toml [[[")
    assert config.charger(f).base == tmp_path / "env.db"
