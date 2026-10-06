# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2050 (vague 0 du plan de simplification) — chaque route de secubox-dns est déclarée UNE fois.

Les routes de zone et d'enregistrement étaient déclarées deux fois : FastAPI applique la PREMIÈRE (version basique),
si bien que la version améliorée — journal des changements et webhooks — était du code mort : /changes et
/webhooks ne recevaient jamais d'événement."""
from unittest import mock

from fastapi.testclient import TestClient

import secubox_core.config as _cfg

# `api.main` lit la config et crée /var/lib/secubox/dns À L'IMPORT : on isole la machine (fichier absent ou illisible,
# répertoire d'état non inscriptible), sans quoi le test ne passerait qu'ailleurs que là où il est lancé.
_cfg._CONFIG = {"global": {}, "api": {"socket_dir": "/tmp/secubox", "jwt_secret": "test"}, "auth": {"users": {}}}
with mock.patch("pathlib.Path.mkdir"):
    from api import main  # noqa: E402


def test_aucune_route_n_est_declaree_deux_fois():
    vus = {}
    for r in main.app.routes:
        for methode in getattr(r, "methods", None) or ():
            if methode in ("HEAD", "OPTIONS"):
                continue
            vus[(methode, r.path)] = vus.get((methode, r.path), 0) + 1
    assert [k for k, n in vus.items() if n > 1] == []


def test_la_creation_d_une_zone_alimente_le_journal_et_les_webhooks(monkeypatch):
    journal, webhooks = [], []

    async def faux_webhooks(event, payload):
        webhooks.append(event)

    monkeypatch.setattr(main, "run_cmd", lambda args, capture=True: (0, "ok", ""))
    monkeypatch.setattr(main, "_record_change", lambda action, details, user="system": journal.append(action))
    monkeypatch.setattr(main, "_trigger_webhooks", faux_webhooks)
    main.app.dependency_overrides[main.require_jwt] = lambda: {"sub": "test"}
    try:
        r = TestClient(main.app).post("/zone", json={"name": "exemple.test"})
    finally:
        main.app.dependency_overrides.clear()
    assert r.status_code == 200 and r.json()["success"] is True
    assert journal == ["zone_created"] and webhooks == ["zone_created"]
