# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3845 — la page appelait /spam/status, /spam/enable et /spam/disable sans route : elles existent, gardées."""
import ast
from pathlib import Path

PKG = Path(__file__).resolve().parents[1]
API = (PKG / "api" / "main.py").read_text(encoding="utf-8")
HTML = (PKG / "www" / "mail" / "index.html").read_text(encoding="utf-8")


def _etat(sortie, ok=True):
    """Exécute `_antispam_etat` tel qu'écrit dans main.py, avec un faux run_cmd."""
    arbre = ast.parse(API)
    fn = next(n for n in arbre.body if isinstance(n, ast.FunctionDef) and n.name == "_antispam_etat")
    ns = {"run_cmd": lambda cmd, timeout=30: (ok, sortie, "")}
    exec(compile(ast.Module(body=[fn], type_ignores=[]), "main.py", "exec"), ns)
    return ns["_antispam_etat"]()


def test_routes_gardees_par_l_administrateur():
    assert '@app.get("/spam/status", dependencies=[Depends(require_jwt)])' in API
    assert '@app.post("/spam/{action}", dependencies=[Depends(require_jwt)])' in API
    bloc = API.split('async def spam_toggle', 1)[1].split("@app.", 1)[0]
    assert '{"enable": "on", "disable": "off"}' in bloc and "HTTPException(400" in bloc


def test_etat_lu_dans_le_conteneur():
    assert _etat("rspamd_unite=enabled\nrspamd_actif=active\nmilter=branche") == \
        {"enabled": True, "running": True, "milter": True}
    assert _etat("rspamd_unite=disabled\nrspamd_actif=inactive\nmilter=absent")["enabled"] is False
    # actif mais milter retiré : Postfix ne l'appelle pas, l'antispam n'est PAS actif
    assert _etat("rspamd_unite=enabled\nrspamd_actif=active\nmilter=absent")["enabled"] is False


def test_etat_inconnu_jamais_inactif():
    assert _etat("conteneur=arrete")["enabled"] is None
    assert _etat("", ok=False)["enabled"] is None


def test_la_page_previent_de_la_perte_dkim():
    assert "plus signé en DKIM" in HTML and "lire('/spam/status')" in HTML
    assert "'/spam/disable'" in HTML and "'/spam/enable'" in HTML
