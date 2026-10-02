# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""La connexion de l'administrateur ouvre le Coffre (#1855), vue d'auth.

Préparer au mot de passe vérifié, confirmer au second facteur réussi —
jamais avant ; rien pour un non-admin ni pour un mauvais mot de passe ; le
mot de passe ne passe qu'au Coffre, jamais au journal."""
import time

import pyotp
import pytest

from test_otp_reseau import MDP, _login, env  # noqa: F401 — banc partagé


@pytest.fixture
def coffre(env, monkeypatch):
    from api import coffre_connexion
    appels = []

    def faux(chemin, corps, delai=10.0):
        appels.append((chemin, dict(corps)))
        if chemin == "/compte/preparer":
            return {"ticket": "T" * 40}
        if chemin == "/personne/preparer":
            return {"ticket": "p." + "P" * 40}
        if chemin == "/compte/confirmer":
            return {"ouvert": True}
        return {"renouvelee": True}
    monkeypatch.setattr(coffre_connexion, "_appel", faux)
    monkeypatch.setattr(coffre_connexion, "_tickets", {})
    return env, appels


def _chemins(appels):
    return [a[0] for a in appels]


def test_lan_sans_second_facteur_exige_ouvre_tout_de_suite(coffre):
    (c, _), appels = coffre
    assert _login(c, "gandalf", lan="1").get("access_token")
    assert _chemins(appels) == ["/compte/preparer", "/compte/confirmer"]
    assert appels[1][1] == {"ticket": "T" * 40, "distante": False}


def test_wan_rien_avant_le_second_facteur(coffre):
    (c, _), appels = coffre
    r = _login(c, "gandalf")
    assert r.get("mfa_required") and _chemins(appels) == ["/compte/preparer"]
    h = {"Authorization": f"Bearer {r['mfa_token']}", "X-SecuBox-LAN": "0"}
    assert c.post("/login/mfa", json={"code": "000000"}, headers=h).status_code == 401
    assert _chemins(appels) == ["/compte/preparer"]                      # mauvais code : rien
    code = pyotp.TOTP("JBSWY3DPEHPK3PXP").now()
    assert c.post("/login/mfa", json={"code": code}, headers=h).status_code == 200
    assert _chemins(appels) == ["/compte/preparer", "/compte/confirmer"]
    assert appels[-1][1] == {"ticket": "T" * 40, "distante": True}


def test_mauvais_mot_de_passe_rien(coffre):
    (c, _), appels = coffre
    c.post("/login", json={"username": "gandalf", "password": "faux"}, headers={"X-SecuBox-LAN": "1"})
    assert appels == []


def test_non_admin_ouvre_sa_personne_pas_le_coffre(coffre):
    """#1855 : un utilisateur ordinaire prépare SON compartiment (/personne/…),
    jamais la clé maîtresse (/compte/preparer)."""
    (c, _), appels = coffre
    assert _login(c, "lecteur", lan="1").get("access_token")
    assert _chemins(appels) == ["/personne/preparer", "/compte/confirmer"]
    assert appels[1][1]["ticket"].startswith("p.")


def test_non_admin_wan_sans_second_facteur_n_ouvre_rien(coffre, monkeypatch):
    (c, _), appels = coffre
    from api import main as m
    monkeypatch.setattr(m, "_otp_exige", lambda request: True)
    # un lecteur SANS TOTP, depuis le WAN : session accordée par la politique, mais le Coffre ne s'ouvre pas
    from secubox_core import user_store
    avant = user_store.get_user
    monkeypatch.setattr(user_store, "get_user",
                        lambda u: {**(avant(u) or {}), "totp": {"enabled": False}} if u == "lecteur" else avant(u))
    _login(c, "lecteur")
    assert "/compte/confirmer" not in _chemins(appels)


def test_changement_de_mot_de_passe_reemballe(coffre):
    (c, _), appels = coffre
    tok = _login(c, "gandalf", lan="1")["access_token"]
    appels.clear()
    r = c.post("/set-password", json={"old_password": MDP, "new_password": "Un-Nouveau-Mot-De-Passe-42!"},
               headers={"Authorization": f"Bearer {tok}"})
    assert r.status_code == 200
    for _ in range(50):
        if appels:
            break
        time.sleep(0.02)
    corps = {"utilisateur": "gandalf", "ancien": MDP, "nouveau": "Un-Nouveau-Mot-De-Passe-42!"}
    for _ in range(50):
        if len(appels) >= 2:
            break
        time.sleep(0.02)
    assert appels == [("/compte/changer", corps), ("/personne/changer", corps)]


def test_le_mot_de_passe_ne_va_pas_au_journal(coffre):
    (c, tmp), _ = coffre
    _login(c, "gandalf", lan="1")
    _login(c, "gandalf")
    assert MDP not in (tmp / "audit.log").read_text()
