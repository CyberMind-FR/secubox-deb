# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""#3732, tâche 4 : compte de service `ai-filtres` et routes `/ai/filtres`.

`secubox-cvectl filtres-ia` est simulé (`filtres_ia._executer`) ; rien ne touche les règles du WAF.
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

COMPOSANT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(COMPOSANT))
sys.path.insert(0, str(Path(__file__).resolve().parent))
POSTINST = COMPOSANT.parents[1] / "debian" / "postinst"
WAFCTL = COMPOSANT / "scripts" / "wafctl"

from test_gestes_ia_3716 import _importer_waf  # noqa: E402

KID = "c" * 64
USAGER = {"sub": "ai-filtres", "compte_service": "ai-filtres", "jti": "a" * 32, "cle": KID}
CTL = ["sudo", "-n", "/usr/sbin/secubox-cvectl", "filtres-ia"]


class FauxCtl:
    def __init__(self):
        self.appels: list[tuple[list[str], bytes]] = []
        self.reponse = (0, json.dumps({"ok": True, "appliques": [{"id": "ia-x"}], "rejets": [], "inchanges": []}), "")
        self.leve = None

    def __call__(self, argv, entree):
        self.appels.append((list(argv), entree))
        if self.leve:
            raise self.leve
        code, sortie, err = self.reponse
        return subprocess.CompletedProcess(argv, code, sortie, err)


@pytest.fixture
def c(monkeypatch, tmp_path):
    from fastapi.testclient import TestClient
    waf = _importer_waf()
    from api import filtres_ia as f
    from secubox_core.compte_service import require_ai_filtres
    monkeypatch.setenv("SECUBOX_WAF_GESTES_IA", "1")
    monkeypatch.setattr(waf, "AUDIT_LOG", tmp_path / "audit.log")
    faux = FauxCtl()
    monkeypatch.setattr(f, "_executer", faux)
    waf.app.dependency_overrides[require_ai_filtres] = lambda: dict(USAGER)

    class B:
        pass
    b = B()
    b.c, b.waf, b.f, b.faux, b.tmp = TestClient(waf.app), waf, f, faux, tmp_path
    b.audit = lambda: ([json.loads(x) for x in (tmp_path / "audit.log").read_text().splitlines()]
                       if (tmp_path / "audit.log").exists() else [])
    try:
        yield b
    finally:
        waf.app.dependency_overrides.clear()


FILTRE = {"cve": "CVE-2026-0001", "pattern": "/x", "categorie": "lfi"}


def test_appliquer_transmet_acteur_et_filtres(c):
    r = c.c.post("/ai/filtres", json={"filtres": [FILTRE]})
    assert r.status_code == 200, r.text
    assert r.json()["appliques"] == [{"id": "ia-x"}]
    argv, entree = c.faux.appels[0]
    assert argv == CTL + ["appliquer", "--apply", "--json"]
    assert json.loads(entree) == {"acteur": f"ai-filtres:{KID}", "filtres": [FILTRE]}
    assert [a["action"] for a in c.audit()] == ["ai-filtres-appliquer"]


def test_51_filtres_422_sans_ctl(c):
    r = c.c.post("/ai/filtres", json={"filtres": [FILTRE] * 51})
    assert r.status_code == 422
    assert c.c.post("/ai/filtres", json={"filtres": []}).status_code == 422
    assert c.c.post("/ai/filtres", json={"filtres": ["x"]}).status_code == 422
    assert c.faux.appels == []


def test_tout_rejete_409(c):
    c.faux.reponse = (0, json.dumps({"ok": True, "appliques": [], "rejets": [{"motif": "x"}], "inchanges": []}), "")
    r = c.c.post("/ai/filtres", json={"filtres": [FILTRE]})
    assert r.status_code == 409 and r.json()["detail"]["motif"] == "rejete"


@pytest.mark.parametrize("code,statut", [(2, 422), (3, 409), (4, 404), (1, 503)])
def test_codes_du_ctl(c, code, statut):
    c.faux.reponse = (code, json.dumps({"ok": False, "erreur": "x"}), "")
    assert c.c.post("/ai/filtres", json={"filtres": [FILTRE]}).status_code == statut


@pytest.mark.parametrize("exc", [subprocess.TimeoutExpired("x", 60), FileNotFoundError("x")])
def test_ctl_injoignable_503_audite(c, exc):
    c.faux.leve = exc
    r = c.c.post("/ai/filtres", json={"filtres": [FILTRE]})
    assert r.status_code == 503 and r.json() == {"detail": {"motif": "ctl"}}
    assert [a["action"] for a in c.audit()] == ["ai-filtres-appliquer"]
    assert "echec" in c.audit()[0]["detail"]


def test_audit_impossible_500(c, monkeypatch):
    def audit(*a):
        raise OSError("plein")
    monkeypatch.setitem(c.f._config, "audit", audit)
    assert c.c.post("/ai/filtres", json={"filtres": [FILTRE]}).status_code == 500
    assert c.c.delete("/ai/filtres/ia-x").status_code == 500


def test_retirer(c):
    c.faux.reponse = (0, json.dumps({"ok": True, "retire": "ia-x"}), "")
    r = c.c.delete("/ai/filtres/ia-x")
    assert r.status_code == 200, r.text
    argv, entree = c.faux.appels[0]
    assert argv == CTL + ["retirer", "--apply", "--json"]
    assert json.loads(entree) == {"acteur": f"ai-filtres:{KID}", "id": "ia-x"}
    assert [a["action"] for a in c.audit()] == ["ai-filtres-retirer"]


def test_retirer_id_invalide_422(c):
    assert c.c.delete("/ai/filtres/pasia").status_code == 422
    assert c.faux.appels == []


def test_lister(c):
    c.faux.reponse = (0, json.dumps({"ok": True, "filtres": []}), "")
    r = c.c.get("/ai/filtres")
    assert r.status_code == 200 and r.json()["filtres"] == []
    argv, entree = c.faux.appels[0]
    assert argv == CTL + ["lister", "--json"] and not entree
    assert [a["action"] for a in c.audit()] == ["ai-filtres-lister"]


def test_routes_gardees_par_ai_filtres_seul():
    waf = _importer_waf()
    from api import filtres_ia as f
    from secubox_core.compte_service import require_ai_ban, require_ai_filtres
    routes = [r for r in waf.app.routes if getattr(r, "path", "").startswith("/ai/filtres")]
    assert {(r.path, tuple(sorted(r.methods))) for r in routes} == {
        ("/ai/filtres", ("POST",)), ("/ai/filtres", ("GET",)), ("/ai/filtres/{fid}", ("DELETE",))}
    for r in routes:
        appels = [d.call for d in r.dependant.dependencies]
        assert require_ai_filtres in appels and require_ai_ban not in appels
        assert appels.index(f.processus_designe) < appels.index(require_ai_filtres)
        assert r.body_field is None


def test_processus_non_designe_503(c, monkeypatch):
    c.waf.app.dependency_overrides.clear()
    monkeypatch.delenv("SECUBOX_WAF_GESTES_IA", raising=False)
    for r in (c.c.post("/ai/filtres", json={"filtres": [FILTRE]}), c.c.get("/ai/filtres"),
              c.c.delete("/ai/filtres/ia-x")):
        assert r.status_code == 503 and r.json() == {"detail": {"motif": "processus"}}
    assert c.faux.appels == [] and c.audit() == []


def test_sans_jeton_401(c):
    c.waf.app.dependency_overrides.clear()
    assert c.c.get("/ai/filtres").status_code == 401


def test_postinst_cree_le_dossier_ai_filtres():
    t = POSTINST.read_text()
    d = "/etc/secubox-comptes-service/ai-filtres"
    assert f"mkdir -p {d}" in t and f"chown root:root {d}" in t and f"chmod 0755 {d}" in t


def test_wafctl_cle_ai_filtres(tmp_path):
    """Même code que cle-ai-ban, autre dossier : la clé se pose sous ai-filtres/, jamais sous ai-ban/."""
    import os
    import shutil
    from test_gestes_ia_3716 import _pub_pem
    from secubox_core import compte_service as cs
    t = WAFCTL.read_text()
    assert "cle-ai-filtres) shift; cmd_cle_ai_filtres" in t
    if not shutil.which("openssl") or not shutil.which("jq"):
        pytest.skip("openssl et jq requis")
    racine, audit = tmp_path / "comptes", tmp_path / "audit.log"
    copie = tmp_path / "wafctl"
    copie.write_text(t.replace('CLES_RACINE="/etc/secubox-comptes-service"', f'CLES_RACINE="{racine}"')
                      .replace('AUDIT_LOG="/var/log/secubox/audit.log"', f'AUDIT_LOG="{audit}"'))
    bin_ = tmp_path / "bin"
    bin_.mkdir()
    (bin_ / "install").write_text('#!/bin/bash\nargs=()\nwhile [ "$#" -gt 0 ]; do\n  case "$1" in -o|-g) shift 2 ;; '
                                  '*) args+=("$1"); shift ;; esac\ndone\nexec /usr/bin/install "${args[@]}"\n')
    (bin_ / "install").chmod(0o755)
    env = {**os.environ, "PATH": f"{bin_}:{os.environ['PATH']}"}

    def lancer(*args):
        return subprocess.run(["bash", str(copie), "cle-ai-filtres", *args], check=False, timeout=30,
                              capture_output=True, text=True, env=env)
    f1, pem1 = _pub_pem(tmp_path, "un.pub")
    r = lancer("ajouter", str(f1))
    assert r.returncode == 0, r.stderr
    kid = cs.empreinte(pem1)
    assert [p.name for p in (racine / "ai-filtres").iterdir()] == [f"{kid}.pub"]
    assert not (racine / "ai-ban").exists()
    assert json.loads(audit.read_text().splitlines()[-1])["action"] == "cle-ai-filtres-ajout"
    assert kid in lancer("lister").stdout
    assert lancer("retirer", kid).returncode == 0
    assert list((racine / "ai-filtres").iterdir()) == []
    assert json.loads(audit.read_text().splitlines()[-1])["action"] == "cle-ai-filtres-retrait"
