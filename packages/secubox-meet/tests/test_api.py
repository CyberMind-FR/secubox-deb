# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""API hôte dédiée de secubox-meet (#3154) : tout passe par `sudo -n meetctl`."""
import asyncio
import fnmatch
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

import httpx
import pytest
from fastapi import HTTPException, Request

RACINE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(RACINE.parents[1] / "common"))
sys.path.insert(0, str(RACINE))

import api.main as M  # noqa: E402


def _jwt(req: Request):
    if req.headers.get("x-test-jwt") != "1":
        raise HTTPException(status_code=401, detail="non authentifié")
    return {"sub": "admin"}


def _lecture(req: Request):
    if req.headers.get("x-test-lecture") != "1":
        raise HTTPException(status_code=401, detail="non authentifié")
    return {"sub": "admin"}


class Client:
    def __init__(self):
        self.appels = []
        self.sorties = {}

    def _req(self, methode, chemin, jwt, lecture, **kw):
        en_tetes = {}
        if jwt:
            en_tetes["x-test-jwt"] = "1"
        if lecture:
            en_tetes["x-test-lecture"] = "1"

        async def go():
            transport = httpx.ASGITransport(app=M.app)
            async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
                return await c.request(methode, chemin, headers=en_tetes, **kw)
        return asyncio.run(go())

    def get(self, chemin, jwt=False, lecture=True):
        return self._req("GET", chemin, jwt, lecture)

    def post(self, chemin, json=None, jwt=False):
        return self._req("POST", chemin, jwt, False, json=json)


@pytest.fixture
def cli(monkeypatch, tmp_path):
    c = Client()
    monkeypatch.setattr(M, "STATUS_CACHE_FILE", tmp_path / "status.json")
    monkeypatch.setattr(M, "CACHE_DIR", tmp_path)
    M._status_cache.update(data=None, ts=0.0)
    M.app.dependency_overrides[M.require_jwt] = _jwt
    M.app.dependency_overrides[M.require_lecture] = _lecture

    def faux(*args, timeout=30):
        c.appels.append(tuple(args))
        return 0, c.sorties.get(args[0], json.dumps({"success": True})), ""
    monkeypatch.setattr(M, "_run_ctl", faux)
    yield c
    M.app.dependency_overrides.clear()


def test_health_libre(cli):
    r = cli.get("/health", lecture=False)
    assert r.status_code == 200 and r.json() == {"status": "ok", "module": "meet"}


def test_media_expose_exige_jwt_et_confirmation(cli):
    assert cli.post("/media-expose", json={"action": "apply"}, jwt=False).status_code == 401
    r = cli.post("/media-expose", json={"action": "apply"}, jwt=True)
    assert r.status_code == 400 and 'confirmer: "meet"' in r.json()["detail"]
    assert cli.post("/media-expose", json={"action": "apply", "confirmer": "autre"}, jwt=True).status_code == 400
    assert not cli.appels
    assert cli.post("/media-expose", json={"action": "apply", "confirmer": "meet"}, jwt=True).status_code == 200
    assert cli.appels[-1] == ("media-expose", "--apply")
    assert cli.post("/media-expose", json={"action": "revoke", "confirmer": "meet"}, jwt=True).status_code == 200
    assert cli.appels[-1] == ("media-expose", "--revoke")


def test_media_expose_action_inconnue_400(cli):
    r = cli.post("/media-expose", json={"action": "detruire", "confirmer": "meet"}, jwt=True)
    assert r.status_code == 400 and not cli.appels


def test_media_expose_lecture(cli):
    assert cli.get("/media-expose", lecture=False).status_code == 401
    assert cli.get("/media-expose").status_code == 200
    assert cli.appels == [("media-expose",)]


def test_control_refuse_une_action_inconnue(cli):
    assert cli.post("/control", json={"action": "destroy"}, jwt=True).status_code == 400 and not cli.appels


def test_control_exige_jwt_et_delegue(cli):
    assert cli.post("/control", json={"action": "restart"}, jwt=False).status_code == 401
    assert cli.post("/control", json={"action": "restart"}, jwt=True).status_code == 200
    assert cli.appels == [("restart",)]


def test_status_lecture_cachee(cli):
    cli.get("/status"); cli.get("/status")
    assert cli.appels.count(("status",)) == 1


def test_status_exige_lecture(cli):
    assert cli.get("/status", lecture=False).status_code == 401 and not cli.appels


def test_status_ecrit_le_cache_fichier(cli):
    cli.get("/status")
    assert json.loads(M.STATUS_CACHE_FILE.read_text()) == {"success": True}


def test_logs_unite_inconnue_400(cli):
    assert cli.get("/logs?unit=sshd", jwt=True).status_code == 400


def test_logs_exige_jwt_et_borne_les_lignes(cli):
    assert cli.get("/logs?unit=livekit", lecture=False).status_code == 401
    cli.sorties["logs"] = "a\nb\n"
    r = cli.get("/logs?unit=livekit&lines=99999", jwt=True)
    assert r.status_code == 200 and r.json() == {"unit": "livekit", "lines": ["a", "b"]}
    assert cli.appels[-1] == ("logs", "livekit", "500")
    cli.get("/logs?unit=nginx&lines=-4", jwt=True)
    assert cli.appels[-1] == ("logs", "nginx", "1")


def test_oidc_verifier_et_enregistrer_exigent_jwt(cli):
    assert cli.get("/oidc", lecture=False).status_code == 401
    assert cli.post("/oidc/enregistrer", json={}, jwt=False).status_code == 401
    assert not cli.appels
    assert cli.get("/oidc", jwt=True).status_code == 200
    assert cli.appels[-1] == ("oidc-verifier",)
    assert cli.post("/oidc/enregistrer", json={}, jwt=True).status_code == 200
    assert cli.appels[-1] == ("oidc-enregistrer",)
    # m1 : l'API n'offre plus le renouvellement (le sudoers ne l'accorde pas) : un champ en trop est ignoré.
    assert cli.post("/oidc/enregistrer", json={"renouveler": True}, jwt=True).status_code == 200
    assert cli.appels[-1] == ("oidc-enregistrer",)
    assert "--renouveler" not in (RACINE / "api" / "main.py").read_text()


def test_erreur_du_ctl_remonte_en_500(cli, monkeypatch):
    monkeypatch.setattr(M, "_run_ctl", lambda *a, timeout=30: (1, "", "boom"))
    r = cli.post("/control", json={"action": "start"}, jwt=True)
    assert r.status_code == 500 and "boom" in r.json()["detail"]


def test_apply_refuse_donne_502_avec_le_message_du_ctl(cli, monkeypatch):
    echec = json.dumps({"success": False, "error": "nft a refusé la règle — rien appliqué"})
    monkeypatch.setattr(M, "_run_ctl", lambda *a, timeout=30: (1, echec, "bruit sur stderr"))
    r = cli.post("/media-expose", json={"action": "apply", "confirmer": "meet"}, jwt=True)
    assert r.status_code == 502 and r.json()["detail"] == "nft a refusé la règle — rien appliqué"


def test_oidc_ko_est_une_reponse_200(cli, monkeypatch):
    ko = json.dumps({"issuer": "https://hall.x/oidc", "discovery": False, "hint": "enregistrer le client"})
    monkeypatch.setattr(M, "_run_ctl", lambda *a, timeout=30: (1, ko, "bruit"))
    r = cli.get("/oidc", jwt=True)
    assert r.status_code == 200 and r.json()["discovery"] is False and r.json()["hint"] == "enregistrer le client"


def test_control_en_echec_json_502(cli, monkeypatch):
    monkeypatch.setattr(M, "_run_ctl", lambda *a, timeout=30: (1, json.dumps({"success": False, "error": "conteneur absent"}), ""))
    r = cli.post("/control", json={"action": "start"}, jwt=True)
    assert r.status_code == 502 and r.json()["detail"] == "conteneur absent"


def test_ecriture_reussie_vide_le_cache_de_statut(cli):
    cli.get("/status")
    assert M.STATUS_CACHE_FILE.exists()
    assert cli.post("/control", json={"action": "restart"}, jwt=True).status_code == 200
    assert not M.STATUS_CACHE_FILE.exists() and M._status_cache["ts"] == 0.0
    cli.get("/status")
    assert cli.appels.count(("status",)) == 2


def test_cache_fichier_non_dict_ignore(cli):
    M.STATUS_CACHE_FILE.write_text("[1, 2]")
    assert cli.get("/status").json() == {"success": True}
    assert cli.appels.count(("status",)) == 1


def test_import_strict_de_l_authentification():
    src = (RACINE / "api" / "main.py").read_text()
    assert "except ImportError" not in src and "from secubox_core.auth import require_jwt, require_lecture" in src


# ── m1 : le sudoers n'accorde QUE les argv exacts que l'API emploie ─────────────────────────────────

SUDOERS = RACINE / "debian" / "secubox-meet.sudoers"


def _regles_sudoers():
    """Les argv accordés à `secubox` (après /usr/sbin/meetctl), un par commande de la liste."""
    texte = re.sub(r"\\\n", " ", SUDOERS.read_text())
    lignes = [li for li in texte.splitlines() if li.strip() and not li.lstrip().startswith("#")]
    regles = []
    for ligne in lignes:
        m = re.match(r"\s*Cmnd_Alias\s+(\w+)\s*=\s*(.*)$", ligne)
        corps = m.group(2) if m else ligne.split("NOPASSWD:", 1)[1]
        for cmd in corps.split(","):
            cmd = cmd.strip()
            if cmd.startswith("/usr/sbin/meetctl"):
                regles.append(cmd[len("/usr/sbin/meetctl"):].strip())
    return regles


def test_sudoers_argv_exacts():
    regles = _regles_sudoers()
    assert "" not in regles                            # jamais « meetctl » nu (tous les arguments)
    unites = ("postgresql", "redis-server", "livekit", "meet-backend", "nginx")
    assert sorted(regles) == sorted(["status", "start", "stop", "restart", "media-expose", "media-expose --apply",
                                     "media-expose --revoke", "oidc-verifier", "oidc-enregistrer"]
                                    + [f"logs {u} [0-9]*" for u in unites])
    assert tuple(unites) == M.KNOWN_UNITS
    t = SUDOERS.read_text()
    assert "secubox ALL=(root) NOPASSWD:" in t and "--renouveler" not in t


def test_chaque_appel_de_l_api_est_accorde_par_le_sudoers(cli):
    regles = _regles_sudoers()
    cli.get("/status")
    cli.get("/media-expose")
    for action in ("start", "stop", "restart"):
        cli.post("/control", json={"action": action}, jwt=True)
    for action in ("apply", "revoke"):
        cli.post("/media-expose", json={"action": action, "confirmer": "meet"}, jwt=True)
    cli.get("/oidc", jwt=True)
    cli.post("/oidc/enregistrer", json={}, jwt=True)
    for unite in M.KNOWN_UNITS:
        cli.get(f"/logs?unit={unite}&lines=7", jwt=True)
    assert len(cli.appels) == 9 + len(M.KNOWN_UNITS)
    for argv in cli.appels:
        assert any(fnmatch.fnmatchcase(" ".join(argv), r) for r in regles), argv


def test_sudoers_valide_par_visudo():
    visudo = shutil.which("visudo") or "/usr/sbin/visudo"
    if not Path(visudo).exists():
        pytest.skip("visudo absent")
    r = subprocess.run([visudo, "-cf", str(SUDOERS)], capture_output=True, text=True, timeout=30)
    assert r.returncode == 0, r.stdout + r.stderr
