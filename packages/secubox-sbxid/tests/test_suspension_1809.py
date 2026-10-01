# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""Suspension effective, base synchronisée, suppression et oubli (#1809)."""
import importlib.util
import json
import sys
import types
from pathlib import Path

import pytest
from fastapi import HTTPException

from test_sbxid_module import _cle, _req, banc  # noqa: F401
from secubox_core import sbxid as S
from api import comptes, main, store

ACCES = Path(__file__).resolve().parents[1] / "acces" / "api"


def _acces_profileur():
    """Le VRAI profileur de la file d'accès, chargé sous un autre nom (les deux
    paquets s'appellent `api`)."""
    if "acces_api" not in sys.modules:
        spec = importlib.util.spec_from_file_location(
            "acces_api", ACCES / "__init__.py", submodule_search_locations=[str(ACCES)])
        m = importlib.util.module_from_spec(spec)
        sys.modules["acces_api"] = m
        spec.loader.exec_module(m)
    import acces_api.profileur as P  # noqa: E402
    return P


@pytest.fixture
def acces(banc, monkeypatch, tmp_path):
    """Faux module acces : vrai Profileur sur le même demandes.json."""
    P = _acces_profileur()
    # Le banc commun omet `message`, champ requis par le vrai profileur.
    b = json.loads(store.DEMANDES.read_text())
    for d in b["demandes"]:
        d.setdefault("message", "")
        d.setdefault("demandee_le", int(__import__("time").time()))
    store.DEMANDES.write_text(json.dumps(b))
    prof = P.Profileur(store.DEMANDES)
    coupes, oublis = [], []
    faux = types.ModuleType("faux_acces_main")
    faux.profileur = lambda: prof
    faux._coupe_sessions = lambda compte, jtis: coupes.append((compte, sorted(jtis)))
    faux.reinscris_manquants = lambda: 0
    monkeypatch.setitem(sys.modules, "faux_acces_main", faux)
    from secubox_core import appareils as _app
    monkeypatch.setattr(_app, "revoque", lambda c: True)
    monkeypatch.setattr(_app, "oublie", lambda c: oublis.append(c) or True)
    from secubox_core import sessions as _reg
    monkeypatch.setattr(_reg, "jtis_du_compte", lambda c: [])
    appels = []
    monkeypatch.setattr(comptes, "helper", lambda d: appels.append((d["service"], d["action"], d["user"])) or {"ok": True})
    return types.SimpleNamespace(prof=prof, coupes=coupes, oublis=oublis, appels=appels)


def _alice():
    ctx = main.exige_admin(_req("tok-g"))
    main._rafraichit()
    r = main.db().execute("SELECT user_uuid FROM sbx_users WHERE pseudo='alice'").fetchone()
    return ctx, r[0]


def test_suspendre_coupe_les_sessions_et_desactive_les_comptes_ouverts_ici(banc, acces):
    ctx, uid = _alice()
    main.db().execute("INSERT INTO sbx_preferences VALUES (?,?,?)", (uid, "ouvert_ici:email", "1"))
    out = main.fixe_statut(uid, main.Statut(status="suspended"), ctx)
    assert out["status"] == "suspended" and out["sessions_coupees"] == 1
    assert ("sbx-" + S.empreinte_cle(banc.pa)[:12], ["jti-a"]) in acces.coupes
    assert acces.appels == [("email", "desactiver", "alice")], "seuls les comptes ouverts ICI"
    # L'appareil n'est PAS révoqué : la réactivation le rend.
    assert main.db().execute("SELECT revoked_at FROM sbx_devices WHERE user_uuid=?", (uid,)).fetchone()[0] is None
    main.fixe_statut(uid, main.Statut(status="active"), ctx)
    assert acces.appels[-1] == ("email", "activer", "alice")


def test_supprimer_exige_la_suspension(banc, acces):
    ctx, uid = _alice()
    with pytest.raises(HTTPException) as e:
        main.supprime_personne(uid, "garder", ctx)
    assert e.value.status_code == 409


def test_supprimer_une_personne_suspendue(banc, acces, tmp_path):
    ctx, uid = _alice()
    main.db().execute("INSERT INTO sbx_preferences VALUES (?,?,?)", (uid, "ouvert_ici:nextcloud", "1"))
    main.db().execute("INSERT INTO sbx_app_links VALUES (?,?,?,?)", (uid, "nextcloud", "alice", "alice"))
    coffre = tmp_path / "coffre" / f"p-{uid}"
    coffre.mkdir(parents=True)
    (coffre / "nextcloud.json").write_text("{}")
    main.fixe_statut(uid, main.Statut(status="suspended"), ctx)
    out = main.supprime_personne(uid, "supprimer", ctx)
    assert out["pseudo"] == "alice" and out["appareils"] == 1
    db = main.db()
    for t in ("sbx_users", "sbx_devices", "sbx_user_roles", "sbx_app_links", "sbx_preferences"):
        assert db.execute(f"SELECT count(*) FROM {t} WHERE user_uuid=?", (uid,)).fetchone()[0] == 0, t
    assert ("nextcloud", "retirer", "alice") in acces.appels
    assert not coffre.exists(), "le coffre de la personne est effacé"
    assert acces.prof.demande_de("did:sbx:y") is None, "sa demande quitte la file"
    assert acces.oublis == ["sbx-" + S.empreinte_cle(banc.pa)[:12]]
    assert db.execute("SELECT count(*) FROM sbx_audit WHERE event='user.deleted'").fetchone()[0] == 1


def test_supprimer_en_gardant_les_comptes(banc, acces):
    ctx, uid = _alice()
    main.db().execute("INSERT INTO sbx_preferences VALUES (?,?,?)", (uid, "ouvert_ici:email", "1"))
    main.fixe_statut(uid, main.Statut(status="suspended"), ctx)
    main.supprime_personne(uid, "garder", ctx)
    assert not [a for a in acces.appels if a[1] == "retirer"]


def test_reconcilie_suit_la_file(banc, acces):
    ctx, uid = _alice()
    did = S.did_appareil(banc.pa)
    b = json.loads(store.DEMANDES.read_text())
    for d in b["demandes"]:
        if d["did"] == "did:sbx:y":
            d["etat"] = "refusee"
    store.DEMANDES.write_text(json.dumps(b))
    assert store.reconcilie(main.db())["revoques"] == 1
    assert main.db().execute("SELECT revoked_at FROM sbx_devices WHERE did=?", (did,)).fetchone()[0]
    for d in b["demandes"]:
        if d["did"] == "did:sbx:y":
            d["etat"] = "acceptee"
    store.DEMANDES.write_text(json.dumps(b))
    assert store.reconcilie(main.db())["retablis"] == 1
    assert main.db().execute("SELECT revoked_at FROM sbx_devices WHERE did=?", (did,)).fetchone()[0] is None


def test_oublier_un_appareil_exige_la_revocation(banc, acces):
    ctx, uid = _alice()
    dev = main.db().execute("SELECT device_uuid FROM sbx_devices WHERE user_uuid=?", (uid,)).fetchone()[0]
    with pytest.raises(HTTPException) as e:
        main.oublie_appareil(dev, ctx)
    assert e.value.status_code == 409
    main.db().execute("UPDATE sbx_devices SET revoked_at=1 WHERE device_uuid=?", (dev,))
    assert main.oublie_appareil(dev, ctx)["ok"]
    assert main.db().execute("SELECT count(*) FROM sbx_devices WHERE device_uuid=?", (dev,)).fetchone()[0] == 0


def test_oublier_une_demande_refusee_seulement(banc, acces):
    ctx = main.exige_admin(_req("tok-g"))
    assert main.oublie_demande("did:sbx:z", ctx)["ok"]                    # refusée
    assert acces.prof.demande_de("did:sbx:z") is None
    with pytest.raises(HTTPException):
        main.oublie_demande("did:sbx:w", ctx)                             # en attente
