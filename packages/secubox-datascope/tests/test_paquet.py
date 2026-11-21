# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3853 — squelette du paquet DataScope : unités, route, confinement, postinst, API, configuration."""
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
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
    # mise à jour : « enable --now » ne relance pas une API déjà active ; restart explicite, première passe aussitôt
    assert "systemctl enable secubox-datascope.service secubox-datascope-collect.timer" in p
    assert "systemctl restart secubox-datascope.service" in p
    assert "systemctl start secubox-datascope-collect.timer" in p
    assert "systemctl start --no-block secubox-datascope-collect.service" in p
    assert "enable --now" not in p
    assert p.index("apparmor_parser") < p.index("systemctl restart") < p.index("--no-block")
    bloc = p[p.index('if [ -d /run/systemd/system ]; then\n            systemctl daemon-reload'):]
    assert p.index("systemctl enable") > p.index('if [ -d /run/systemd/system ]; then\n            systemctl daemon')
    for ligne in bloc.splitlines():
        if ligne.strip().startswith("systemctl ") and "daemon-reload" not in ligne:
            assert ligne.rstrip().endswith("|| true"), ligne


def test_postrm_decharge_apparmor_et_recharge_nginx():
    p = _lire("debian/postrm")
    assert re.search(r"^\s*remove\|purge\)", p, re.M) or "remove|purge)" in p
    assert "apparmor_parser -R /etc/apparmor.d/secubox-datascope" in p
    assert "command -v apparmor_parser" in p
    assert "nginx -t" in p and "systemctl reload nginx" in p
    assert p.index("apparmor_parser -R") < p.index("rm -f /etc/secubox/datascope.toml /etc/apparmor.d/secubox-datascope")


def test_scripts_mainteneur_sh_n():
    for nom in ("postinst", "postrm", "prerm"):
        r = subprocess.run(["sh", "-n", str(RACINE / "debian" / nom)], capture_output=True, text=True)
        assert r.returncode == 0, (nom, r.stderr)


def test_menu_ordre_suit_le_prefixe():
    for f in (RACINE / "menu.d").glob("*.json"):
        assert json.loads(f.read_text(encoding="utf-8"))["order"] == int(f.name.split("-", 1)[0]), f.name


def test_rules_installe_tout_le_paquet_python(tmp_path):
    """Exécute la cible d'installation de debian/rules dans un dossier jetable : tout .py du paquet (connecteurs
    compris), toute route d'API et toute migration doivent y être, sans __pycache__."""
    if not shutil.which("make") or not shutil.which("install"):
        pytest.skip("make ou install absent")
    dest = tmp_path / "pkg"
    r = subprocess.run(["make", "-s", "-f", "debian/rules", "override_dh_auto_install", f"P={dest}"],
                       cwd=RACINE, capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    lib = dest / "usr/lib/secubox/datascope"
    attendus = [p.relative_to(RACINE) for motif in ("secubox_datascope/**/*.py", "api/*.py", "migrations/*.sql")
                for p in RACINE.glob(motif) if "__pycache__" not in p.parts]
    assert Path("secubox_datascope/connecteurs/network.py") in attendus
    manquants = [str(a) for a in attendus if not (lib / a).is_file()]
    assert not manquants, manquants
    assert not list(lib.rglob("__pycache__")) and not list(lib.rglob("*.pyc"))


def test_control():
    c = _lire("debian/control")
    assert "Standards-Version: 4.6.2" in c
    assert "Architecture: all" in c
    assert "python3-fastapi" in c and "python3-uvicorn" in c and "secubox-core" in c
    assert _lire("debian/compat").strip() == "13"
    assert _lire("debian/changelog").startswith("secubox-datascope (0.1.1-1~trixie1) trixie;")


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
