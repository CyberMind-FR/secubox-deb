# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3338 volet 3 — la boutique suit la formule de la box : une app hors formule est annoncée « Disponible avec la
formule X » et le SERVEUR refuse son installation. Fail-closed : sans abonnement, rien, sauf le marqueur root
`abonnement-libre` (maître, atelier). Le profil est désigné par le nom de son fichier, partout."""
import importlib
import json
import subprocess
import sys
from pathlib import Path

import pytest

PKG = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PKG))
sys.path.insert(0, str(PKG.parents[1] / "common"))
from fastapi.testclient import TestClient  # noqa: E402


@pytest.fixture()
def api(monkeypatch, tmp_path):
    monkeypatch.setenv("APPSTORE_RACINE", str(tmp_path))
    prof = tmp_path / "etc/secubox/profiles"
    prof.mkdir(parents=True)
    # `name` différent du nom de fichier : seule la clé fichier compte (#3338, point 5)
    (prof / "lite.toml").write_text('name = "autre"\non = ["dns"]\n')
    (prof / "media-lab.toml").write_text('on = ["dns", "secubox-jellyfin"]\n')
    import api.main as m
    importlib.reload(m)
    m.app.dependency_overrides[m.require_jwt] = lambda: {"sub": "admin"}
    m.app.dependency_overrides[m.require_lecture] = lambda: {"sub": "admin"}
    monkeypatch.setattr(m, "load_catalog", lambda: [{"name": "secubox-dns", "tier": "lite"},
                                                    {"name": "secubox-jellyfin", "tier": "lite"}])
    monkeypatch.setattr(m, "compute_state", lambda force=False: {
        "secubox-dns": {"name": "secubox-dns", "category": "network", "tier": "lite", "installed": False,
                        "state": "available", "running": False},
        "secubox-jellyfin": {"name": "secubox-jellyfin", "category": "media", "tier": "lite", "installed": False,
                             "state": "available", "running": False}})
    monkeypatch.setattr(m, "_profils", lambda: [])
    monkeypatch.setattr(m, "_appstorectl", lambda argv: (0, "ok", ""))
    m.racine = tmp_path
    yield m
    m.app.dependency_overrides.clear()


def _abonne(m, **kw):
    d = {"formule": "Léger", "profil": "lite", "statut": "actif",
         "formules": [{"nom": "Léger", "profil": "lite"}, {"nom": "Médias", "profil": "media-lab"}]}
    d.update(kw)
    (m.racine / "etc/secubox/abonnement.json").write_text(json.dumps(d), encoding="utf-8")


def test_sans_abonnement_rien_ne_s_installe(api):
    c = TestClient(api.app)
    mods = {x["name"]: x for x in c.get("/catalog").json()["modules"]}
    assert mods["secubox-jellyfin"]["hors_formule"] is True
    r = c.post("/module/secubox-dns/action/install")
    assert r.status_code == 403 and "abonnement" in r.json()["detail"]


def test_marqueur_libre_maitre_ou_atelier(api):
    (api.racine / "etc/secubox/abonnement-libre").write_text("")
    (api.racine / "etc/secubox/abonnement-libre").chmod(0o644)
    c = TestClient(api.app)
    assert not {x["name"]: x for x in c.get("/catalog").json()["modules"]}["secubox-jellyfin"]["hors_formule"]
    assert c.post("/module/secubox-jellyfin/action/install").status_code == 202


def test_hors_formule_annonce_et_refuse_par_le_serveur(api):
    _abonne(api)
    c = TestClient(api.app)
    mods = {x["name"]: x for x in c.get("/catalog").json()["modules"]}
    assert mods["secubox-jellyfin"]["hors_formule"] is True
    assert mods["secubox-jellyfin"]["formule_requise"] == "Médias"
    assert not mods["secubox-dns"].get("hors_formule")
    r = c.post("/module/secubox-jellyfin/action/install")
    assert r.status_code == 403 and "Médias" in r.json()["detail"]
    assert c.post("/module/secubox-dns/action/install").status_code == 202


@pytest.mark.parametrize("statut", ["suspendu", "echu", "revoque"])
def test_abonnement_inactif_refuse_toute_installation(api, statut):
    _abonne(api, statut=statut)
    r = TestClient(api.app).post("/module/secubox-dns/action/install")
    assert r.status_code == 403 and "abonnement" in r.json()["detail"]


def test_fichier_illisible_refuse(api):
    (api.racine / "etc/secubox/abonnement.json").write_text("{pas du json", encoding="utf-8")
    r = TestClient(api.app).post("/module/secubox-dns/action/install")
    assert r.status_code == 403


def test_appstorectl_applique_la_meme_regle(tmp_path):
    """Point 6 : la frontière root (secubox-appstorectl) refuse aussi ; elle appelle le même module."""
    ctl = (PKG / "sbin/secubox-appstorectl").read_text()
    assert "abonnement.py" in ctl
    script = PKG / "api/abonnement.py"
    env = {"APPSTORE_RACINE": str(tmp_path), "PATH": "/usr/bin:/bin"}
    r = subprocess.run([sys.executable, "-I", str(script), "secubox-dns"], env=env, capture_output=True, text=True)
    assert r.returncode == 3 and "abonnement" in r.stderr
    (tmp_path / "etc/secubox").mkdir(parents=True)
    (tmp_path / "etc/secubox/abonnement-libre").write_text("")
    (tmp_path / "etc/secubox/abonnement-libre").chmod(0o644)
    r = subprocess.run([sys.executable, "-I", str(script), "secubox-dns"], env=env, capture_output=True, text=True)
    assert r.returncode == 0


# ── « Libre » sur signal POSITIF seulement (re-relecture #3343) ─────────────────────────────────────────────────

def _droit(r, nom="secubox-jellyfin"):
    import importlib.util
    spec = importlib.util.spec_from_file_location("abonnement_t", PKG / "api/abonnement.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.droit(nom, str(r))


def test_absence_n_est_jamais_libre(tmp_path):
    (tmp_path / "etc/secubox").mkdir(parents=True)
    assert _droit(tmp_path)[0] is False


def test_libre_maitre_du_parc(tmp_path):
    (tmp_path / "var/lib/dpkg/info").mkdir(parents=True)
    (tmp_path / "var/lib/dpkg/info/secubox-fonction-maitre.list").write_text("")
    assert _droit(tmp_path)[0] is True


def test_libre_box_du_proprietaire_drapeau_valide(tmp_path):
    import time
    d = tmp_path / "etc/secubox-pilotage"
    d.mkdir(parents=True)
    f = d / "proprietaire"
    f.write_text(f"{int(time.time()) + 3600}\n")
    f.chmod(0o644)
    assert _droit(tmp_path)[0] is True
    f.write_text(f"{int(time.time()) - 10}\n")                 # échu
    assert _droit(tmp_path)[0] is False
    f.write_text("pas un nombre\n")
    assert _droit(tmp_path)[0] is False
    f.write_text(f"{int(time.time()) + 3600}\n")
    f.chmod(0o666)                                             # inscriptible par d'autres
    assert _droit(tmp_path)[0] is False


def test_libre_marqueur_operateur(tmp_path):
    (tmp_path / "etc/secubox").mkdir(parents=True)
    (tmp_path / "etc/secubox/abonnement-libre").write_text("")
    (tmp_path / "etc/secubox/abonnement-libre").chmod(0o644)
    assert _droit(tmp_path)[0] is True


def test_postinst_ne_pose_plus_le_marqueur():
    post = (PKG / "debian/postinst").read_text()
    assert "--poser-libre" not in post and "abonnement-libre" not in post


def test_appstorectl_ignore_la_racine_de_test():
    ctl = (PKG / "sbin/secubox-appstorectl").read_text()
    assert "unset APPSTORE_RACINE" in ctl.split("set -euo pipefail", 1)[1][:400]
