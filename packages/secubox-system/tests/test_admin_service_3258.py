# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3258 (revue I2) — /admin/service/<nom>/<action> passe par le MÊME contrôle que /system/service_control.

CONSTAT : `POST /api/v1/admin/service/secubox-auth/stop` tournait en root (secubox-admin.service, User=root, donc sans
polkit), sans motif, sans « -- », sans liste protégée : la page /admin/ contournait le 403 de service_control.
Parade : un seul helper, secubox_core.unites.piloter, appelé par les deux routes (pas une copie)."""
import asyncio
import importlib.util
import json
import subprocess
import sys
from pathlib import Path
from unittest import mock

import pytest
from fastapi import HTTPException

PAQUETS = Path(__file__).resolve().parents[2]
SYSTEM = PAQUETS / "secubox-system"
ADMIN = SYSTEM / "composants" / "admin" / "api" / "main.py"
sys.path.insert(0, str(PAQUETS.parent / "common"))

from secubox_core import unites  # noqa: E402

SORTIE = "SORTIE-DE-SYSTEMCTL-A-NE-PAS-AUDITER"


def _charge(chemin: Path, nom: str):
    spec = importlib.util.spec_from_file_location(nom, chemin)
    m = importlib.util.module_from_spec(spec)
    # /var/lib/secubox/admin est créé à l'import : rien à créer sur un poste de test.
    with mock.patch.object(Path, "mkdir", lambda *a, **k: None):
        spec.loader.exec_module(m)
    return m


@pytest.fixture(scope="module")
def admin():
    return _charge(ADMIN, "api_admin_3258")


@pytest.fixture
def banc(monkeypatch, tmp_path):
    etat = {"appels": [], "rc": 0, "audit": tmp_path / "audit.log"}

    def run(argv, *a, **k):
        etat["appels"].append(list(argv))
        if etat["rc"]:
            raise subprocess.CalledProcessError(etat["rc"], argv, output="", stderr=SORTIE)
        return subprocess.CompletedProcess(argv, 0, SORTIE, "")

    monkeypatch.setattr(unites.subprocess, "run", run)
    monkeypatch.setattr(unites, "AUDIT_LOG", etat["audit"], raising=False)
    return etat


def _audit(banc):
    if not banc["audit"].exists():
        return []
    return [json.loads(x) for x in banc["audit"].read_text(encoding="utf-8").splitlines() if x.strip()]


ROUTES = {"start": "start_service", "stop": "stop_service", "restart": "restart_service"}


def _appelle(admin, action, nom):
    return asyncio.run(getattr(admin, ROUTES[action])(nom, user={"sub": "admin"}))


def test_l_admin_n_arrete_plus_une_unite_protegee(admin, banc):
    with pytest.raises(HTTPException) as e:
        _appelle(admin, "stop", "secubox-auth")
    assert e.value.status_code == 403 and "unité protégée" in e.value.detail
    assert banc["appels"] == []
    a = _audit(banc)
    assert len(a) == 1 and a[0]["module"] == "admin" and a[0]["resultat"] == "refuse" and a[0]["code"] == 403
    assert a[0]["unite"] == "secubox-auth.service" and a[0]["acteur"] == "admin"


@pytest.mark.parametrize("nom", ["nftables", "-H root@ailleurs", "--now", "secubox-hub.timer", "systemd-networkd"])
def test_l_admin_refuse_un_nom_hors_motif(admin, banc, nom):
    with pytest.raises(HTTPException) as e:
        _appelle(admin, "stop", nom)
    assert e.value.status_code == 400 and banc["appels"] == []
    assert _audit(banc)[0]["resultat"] == "refuse"


@pytest.mark.parametrize("action", ["start", "restart"])
def test_l_admin_repare_un_protege_avec_double_tiret(admin, banc, action):
    r = _appelle(admin, action, "secubox-waf-ng")
    assert r["success"] is True and r["unit"] == "secubox-waf-ng.service" and r["action"] == action
    assert banc["appels"] == [["systemctl", action, "--", "secubox-waf-ng.service"]]
    a = _audit(banc)
    assert len(a) == 1 and a[0]["module"] == "admin" and a[0]["resultat"] == "ok"


def test_l_admin_arrete_une_unite_non_protegee_et_l_audit_ne_garde_pas_la_sortie(admin, banc):
    r = _appelle(admin, "stop", "secubox-dpi")
    assert r["success"] is True and banc["appels"] == [["systemctl", "stop", "--", "secubox-dpi.service"]]
    assert SORTIE not in banc["audit"].read_text(encoding="utf-8")


def test_l_echec_garde_la_raison_pour_la_page(admin, banc):
    """La page /admin/ affiche `stderr` d'un échec."""
    banc["rc"] = 1
    r = _appelle(admin, "restart", "secubox-dpi")
    assert r["success"] is False and SORTIE in r["stderr"]
    assert _audit(banc)[0]["resultat"] == "echec"


def test_un_seul_helper_partage_par_system_et_admin(admin):
    """Factorisation : les deux API appellent secubox_core.unites, aucune ne garde sa propre liste ni son systemctl."""
    systeme = _charge(SYSTEM / "api" / "main.py", "api_systeme_3258_i2")
    assert systeme.unites is unites and admin.unites is unites
    for src in (ADMIN.read_text(encoding="utf-8"), (SYSTEM / "api" / "main.py").read_text(encoding="utf-8")):
        assert "UNITES_PROTEGEES = frozenset" not in src and "MOTIF_UNITE = re.compile" not in src
    src = ADMIN.read_text(encoding="utf-8")
    relais = src.split("async def _piloter(", 1)[1].split("\n@", 1)[0]
    assert "unites.piloter" in relais and "systemctl" not in relais
    for route in ROUTES.values():
        corps = src.split(f"async def {route}(", 1)[1].split("\n@", 1)[0]
        assert "_piloter(name, " in corps and "systemctl" not in corps and "_run_cmd" not in corps, route


# ---------- tour 2, ruling R2 : quatre unités Debian réparables depuis /admin/, jamais arrêtées ----------
# /admin/ liste TOUS les services systemd. nginx, haproxy, unbound et ssh gardent start, restart (et reload, permis
# par le contrôle partagé) ; stop est refusé (403) ; toute autre unité hors secubox-* reste refusée (400).
DEBIAN = ["nginx", "haproxy", "unbound", "ssh"]


@pytest.mark.parametrize("nom", DEBIAN)
@pytest.mark.parametrize("action", ["start", "restart"])
def test_l_admin_repare_une_unite_debian_de_la_liste(admin, banc, nom, action):
    r = _appelle(admin, action, nom)
    assert r["success"] is True and r["unit"] == f"{nom}.service"
    assert banc["appels"] == [["systemctl", action, "--", f"{nom}.service"]]
    a = _audit(banc)
    assert len(a) == 1 and a[0]["module"] == "admin" and a[0]["resultat"] == "ok" and a[0]["unite"] == f"{nom}.service"


@pytest.mark.parametrize("nom", DEBIAN + ["nginx.service"])
def test_l_admin_n_arrete_jamais_une_unite_debian_de_la_liste(admin, banc, nom):
    with pytest.raises(HTTPException) as e:
        _appelle(admin, "stop", nom)
    assert e.value.status_code == 403 and "arrêt refusé" in e.value.detail
    assert banc["appels"] == []
    a = _audit(banc)
    assert len(a) == 1 and a[0]["resultat"] == "refuse" and a[0]["code"] == 403


@pytest.mark.parametrize("nom", ["nftables", "nftables.service", "systemd-networkd", "apache2", "unbound-resolvconf"])
def test_l_admin_refuse_une_unite_debian_hors_liste(admin, banc, nom):
    with pytest.raises(HTTPException) as e:
        _appelle(admin, "restart", nom)
    assert e.value.status_code == 400 and banc["appels"] == []
    a = _audit(banc)
    assert len(a) == 1 and a[0]["resultat"] == "refuse" and a[0]["code"] == 400


def test_le_rechargement_d_une_unite_debian_est_permis_par_l_option(banc):
    r = unites.piloter("admin", "admin", "reload", "nginx", avec_unites_debian=True)
    assert r["success"] is True and banc["appels"] == [["systemctl", "reload", "--", "nginx.service"]]


def test_sans_l_option_aucune_unite_debian(banc):
    """service_control (secubox-system) n'active jamais l'option : secubox-* seulement."""
    with pytest.raises(HTTPException) as e:
        unites.piloter("system", "admin", "restart", "nginx")
    assert e.value.status_code == 400 and banc["appels"] == []
    systeme = (SYSTEM / "api" / "main.py").read_text(encoding="utf-8")
    assert "avec_unites_debian" not in systeme
    assert "avec_unites_debian=True" in ADMIN.read_text(encoding="utf-8")


def test_la_liste_debian_est_courte_et_nommee():
    assert unites.UNITES_DEBIAN_ADMIN == frozenset({"nginx.service", "haproxy.service", "unbound.service", "ssh.service"})
