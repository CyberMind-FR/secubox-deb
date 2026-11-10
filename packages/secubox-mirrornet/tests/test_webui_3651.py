# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3651 — interface web MirrorNet (test statique, AURORA-REFERENCE § 11) et routes d'approbation / refus."""
import importlib
import json
import re
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

ICI = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ICI))
sys.path.insert(0, str(Path(__file__).resolve().parent))
PAGE = (ICI / "www" / "mirrornet" / "index.html").read_text(encoding="utf-8")

from test_cycle_3647 import Noeud, abonnement, export, offre  # noqa: E402

from secubox_mirrornet import schema  # noqa: E402


def test_page_conforme_aurora():
    assert "SPDX-License-Identifier: LicenseRef-CMSD-1.0" in PAGE
    assert "sbxVue" in PAGE and "onglet: 'mirrornet'" in PAGE
    assert "?demo=1" in PAGE and "DEMO" in PAGE and "?embed=1" in PAGE
    externes = [s for s in re.findall(r'<script[^>]*src="([^"]+)"', PAGE) if s != "/shared/sidebar.js"]
    assert externes == []
    for interdit in ("confirm(", "alert(", "prompt(", "lorem", "innerHTML", "document.write", "min-height:100vh"):
        assert interdit not in PAGE, interdit
    assert "sbx_token" in PAGE and "X-Idempotence" in PAGE


def test_routes_de_la_page_existent_dans_l_api():
    main = importlib.import_module("api.main")
    routes = {(m, r.path) for r in main.app.routes for m in getattr(r, "methods", ())}
    attendues = {("GET", "/api/v1/mirrornet/status"), ("GET", "/api/v1/mirrornet/services"),
                 ("GET", "/api/v1/mirrornet/subscriptions"), ("GET", "/api/v1/mirrornet/subscriptions/{subscription_id}"),
                 ("POST", "/api/v1/mirrornet/services/{service_id}/subscribe"),
                 ("POST", "/api/v1/mirrornet/subscriptions/{subscription_id}/renew"),
                 ("POST", "/api/v1/mirrornet/subscriptions/{subscription_id}/approve"),
                 ("POST", "/api/v1/mirrornet/subscriptions/{subscription_id}/reject"),
                 ("DELETE", "/api/v1/mirrornet/subscriptions/{subscription_id}"),
                 ("POST", "/api/v1/mirrornet/services/publish")}
    assert attendues <= routes
    for chemin in ("'/status'", "'/services'", "'/subscriptions'", "/subscribe'", "/renew'", "/approve'", "/reject'",
                   "'DELETE'", "'/services/publish'"):
        assert chemin in PAGE, chemin


def test_aucune_ecriture_en_demonstration():
    corps = PAGE[PAGE.index("async function ecrire("):]
    assert corps.index("if (DEMO)") < corps.index("await api(chemin, opts)")


def test_menu():
    m = json.loads((ICI / "menu.d" / "576-mirrornet.json").read_text())
    assert m["path"] == "/mirrornet/" and m["category"] == "mesh"
    regles = (ICI / "debian" / "rules").read_text()
    assert "www/mirrornet/index.html" in regles and "menu.d/576-mirrornet.json" in regles


@pytest.fixture
def api(tmp_path, monkeypatch):
    from secubox_mirrornet import config
    import secubox_core.auth as auth
    main = importlib.import_module("api.main")
    monkeypatch.setattr(auth, "_validate_token", lambda t: {"sub": "admin"} if t.startswith("jeton") else None)
    monkeypatch.setattr(config, "BASE", tmp_path / "m.db")
    monkeypatch.setattr(config, "EXPORT", tmp_path / "export.json")
    monkeypatch.setattr(config, "CONF", tmp_path / "absent.toml")
    schema.initialiser(tmp_path / "m.db")
    main.app.dependency_overrides[main.require_lecture] = lambda: {"sub": "lecteur"}
    main.app.dependency_overrides[main.require_jwt] = lambda: {"sub": "admin"}
    yield main, tmp_path
    main.app.dependency_overrides.clear()


def test_approbation_par_le_fournisseur_seulement(api, monkeypatch):
    main, tmp = api
    moi, abonne_ = Noeud("gk6"), Noeud("gk12")
    o = offre(moi, approval_mode="pending")
    s = abonnement(abonne_, o["payload"]["service_id"])
    sub_id = s["payload"]["subscription_id"]
    o2 = offre(abonne_)
    s_moi = abonnement(moi, o2["payload"]["service_id"])                # ce nœud abonné ailleurs
    ex = export(moi, [o, s, o2, s_moi], [(moi, "LIMITED"), (abonne_, "LIMITED")])
    (tmp / "export.json").write_text(json.dumps(ex))
    main.synchroniser_maintenant()
    appels = []
    monkeypatch.setattr(main.annuaire, "appeler", lambda ch, corps, j, **k: appels.append(ch) or (200, {"status": "approved"}))
    c = TestClient(main.app)
    c.headers["Authorization"] = "Bearer jeton-admin"
    assert c.post(f"/api/v1/mirrornet/subscriptions/{sub_id}/approve").status_code == 200
    assert appels == [f"/self/subscription/{sub_id}/approve"]
    # Ce nœud abonné (pas fournisseur) : refus local, aucun relais.
    r = c.post(f"/api/v1/mirrornet/subscriptions/{s_moi['payload']['subscription_id']}/reject")
    assert r.status_code == 409 and len(appels) == 1
