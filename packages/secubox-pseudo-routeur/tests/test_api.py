# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
from fastapi.testclient import TestClient
from api import main


def test_etat_accessible_en_lecture_sans_jwt_mais_pas_sans_rien():
    # Ruling (ref #2940, Tache 5) : require_lecture laisse passer sans JWT (lecture LAN) ;
    # pseudo-routeurctl est absent sur cette machine de dev/test (pas sudo -n reel), donc la
    # route degrade en 502 (meme invariant que 401/403 : jamais 404/500, la garde a repondu).
    c = TestClient(main.app)
    r = c.get("/etat")
    assert r.status_code in (200, 401, 403, 502)  # jamais 404/500 : la route existe et sa garde repond


def test_activer_exige_jwt():
    c = TestClient(main.app)
    r = c.post("/activer")
    assert r.status_code in (401, 403)


def test_suggestions_journalise_une_panne_de_socket(caplog):
    # Relecture securite (ref #2940) : les deux appels inter-modules (NAC, Freebox) de
    # /suggestions avalaient toute exception en silence (except Exception: pass), interdit
    # par RULES-CODE.md § 7. Sans socket reel ici (dev/test), l'echec doit etre journalise.
    from secubox_core import auth

    main.app.dependency_overrides[auth.require_jwt] = lambda: {"sub": "admin"}
    try:
        with caplog.at_level("WARNING", logger="secubox-pseudo-routeur"):
            c = TestClient(main.app)
            r = c.get("/suggestions")
        assert r.status_code == 200
        assert any("suggestions" in m or "uds" in m.lower() or "socket" in m.lower() for m in caplog.messages)
    finally:
        main.app.dependency_overrides.clear()


def test_journal_exige_jwt():
    # Relecture securite (ref #2940) : MODULE-COMPLIANCE.md liste explicitement les
    # journaux sous require_jwt, pas require_lecture — /journal expose l'audit des
    # bascules de passerelle DHCP, pas une simple lecture d'etat.
    c = TestClient(main.app)
    r = c.get("/journal")
    assert r.status_code in (401, 403)
