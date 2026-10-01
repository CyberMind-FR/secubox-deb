# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""Invitations : le lien fait entrer une personne ou un appareil de plus (#1816)."""
import asyncio
import json
import sys
import types
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric import utils as asym_utils
from fastapi import HTTPException
from starlette.requests import Request

from test_sbxid_module import _req, banc  # noqa: F401
from test_suspension_1809 import _acces_profileur
from secubox_core import sbxid as S
from api import invitations, main, store

ACCES = Path(__file__).resolve().parents[1] / "acces" / "api"


def _paire():
    k = ec.generate_private_key(ec.SECP256R1())
    pub = k.public_key().public_bytes(serialization.Encoding.X962,
                                      serialization.PublicFormat.UncompressedPoint).hex()
    return k, pub


def _signe(k, message: bytes) -> str:
    r, s = asym_utils.decode_dss_signature(k.sign(message, ec.ECDSA(hashes.SHA256())))
    return (r.to_bytes(32, "big") + s.to_bytes(32, "big")).hex()


def _req_publique():
    return Request({"type": "http", "method": "POST", "path": "/", "headers": [],
                    "client": ("192.168.1.50", 5000)})


@pytest.fixture
def invit(banc, monkeypatch):
    P = _acces_profileur()
    import acces_api.identite as I
    b = json.loads(store.DEMANDES.read_text())
    for d in b["demandes"]:
        d.setdefault("message", "")
        d.setdefault("demandee_le", int(__import__("time").time()))
    store.DEMANDES.write_text(json.dumps(b))
    prof = P.Profileur(store.DEMANDES)
    faux = types.ModuleType("faux_acces_main")

    class Verdict:
        def __init__(self, did, motif=""):
            self.did = did

    async def accepter(v, req):
        prof.accepte(v.did, par="test")
        return {"ok": True}
    faux.profileur, faux.Verdict, faux.accepter = (lambda: prof), Verdict, accepter
    faux.verifie_signature = I.verifie_signature
    faux._coupe_sessions = lambda *a: None
    faux.reinscris_manquants = lambda: 0
    monkeypatch.setitem(sys.modules, "faux_acces_main", faux)
    travaux = []
    monkeypatch.setattr(main, "_travail", lambda uid, faire, ev, acteur: travaux.append((uid, acteur)) or {})
    monkeypatch.setattr(main, "_CADENCE_PUBLIQUE", {})
    main._rafraichit()
    return types.SimpleNamespace(prof=prof, travaux=travaux)


def _code(lien):
    return lien.split("invitation=", 1)[1]


def _rejoint(code, k, pub, nom=""):
    return asyncio.run(main.rejoint(main.Rejoindre(code=code, did=S.did_appareil(pub), cle_publique=pub,
                                                   signature=_signe(k, code.encode()), nom=nom,
                                                   appareil="Pixel"), _req_publique()))


def test_une_invitation_fait_entrer_une_personne(banc, invit):
    ctx = main.moi(_req("tok-g"))
    r = main.cree_invitation(main.Invitation(role="member", pseudo="ana", email="ana@exemple.org"), ctx)
    assert r["sorte"] == "personne" and "invitation=" in r["lien"] and "code" not in r
    k, pub = _paire()
    out = _rejoint(_code(r["lien"]), k, pub, nom="Ana")
    assert out["pseudo"] == "ana" and out["jeton"]
    p = main.db().execute("SELECT user_uuid, email FROM sbx_users WHERE pseudo='ana'").fetchone()
    assert p["email"] == "ana@exemple.org"
    assert [x[0] for x in main.db().execute("SELECT role_id FROM sbx_user_roles WHERE user_uuid=?",
                                            (p["user_uuid"],))] == ["member"]
    assert invit.prof.demande_de(S.did_appareil(pub)).etat == "acceptee"
    assert invit.travaux and invit.travaux[0][0] == p["user_uuid"], "ses services s'ouvrent"
    # usage UNIQUE
    k2, pub2 = _paire()
    with pytest.raises(HTTPException) as e:
        _rejoint(_code(r["lien"]), k2, pub2)
    assert e.value.status_code == 404


def test_sans_la_cle_on_ne_rejoint_pas(banc, invit):
    r = main.cree_invitation(main.Invitation(role="guest"), main.moi(_req("tok-g")))
    k, pub = _paire()
    autre, _ = _paire()
    code = _code(r["lien"])
    with pytest.raises(HTTPException) as e:
        asyncio.run(main.rejoint(main.Rejoindre(code=code, did=S.did_appareil(pub), cle_publique=pub,
                                                signature=_signe(autre, code.encode())), _req_publique()))
    assert e.value.status_code == 403
    _rejoint(code, k, pub)                 # l'invitation n'a pas été brûlée par l'essai


def test_une_invitation_revoquee_ne_sert_plus(banc, invit):
    ctx = main.moi(_req("tok-g"))
    r = main.cree_invitation(main.Invitation(role="guest"), ctx)
    assert main.revoque_invitation(r["invite_uuid"], ctx)["ok"]
    k, pub = _paire()
    with pytest.raises(HTTPException):
        _rejoint(_code(r["lien"]), k, pub)


def test_un_membre_n_invite_que_des_invites(banc, invit):
    ctx_a = main.moi(_req("tok-a"))                   # alice : membre
    with pytest.raises(HTTPException) as e:
        main.cree_invitation(main.Invitation(role="member"), ctx_a)
    assert e.value.status_code == 403
    r = main.cree_invitation(main.Invitation(role="guest"), ctx_a)
    assert r["sorte"] == "personne"
    assert [i["invite_uuid"] for i in main.liste_invitations(ctx_a)["invitations"]] == [r["invite_uuid"]]


def test_ajouter_un_appareil_a_sa_personne(banc, invit):
    ctx_a = main.moi(_req("tok-a"))
    r = main.invite_un_appareil(ctx_a)
    assert r["sorte"] == "appareil" and r["expire_le"] - __import__("time").time() <= 600
    k, pub = _paire()
    out = _rejoint(_code(r["lien"]), k, pub)
    assert out["sorte"] == "appareil" and out["pseudo"] == "alice"
    dev = store.appareil_par_did(main.db(), S.did_appareil(pub))
    alice = main.db().execute("SELECT user_uuid FROM sbx_users WHERE pseudo='alice'").fetchone()[0]
    assert dev["user_uuid"] == alice
    assert invit.travaux == [], "un appareil de plus n'ouvre pas de comptes"


def test_un_appareil_deja_admis_ne_change_pas_de_personne(banc, invit):
    r = main.cree_invitation(main.Invitation(role="guest"), main.moi(_req("tok-g")))
    with pytest.raises(HTTPException) as e:
        _rejoint(_code(r["lien"]), banc.ka, banc.pa)  # l'appareil d'alice, déjà admis
    assert e.value.status_code == 409


def test_seule_l_empreinte_du_code_est_gardee(banc, invit):
    r = main.cree_invitation(main.Invitation(role="guest"), main.moi(_req("tok-g")))
    code = _code(r["lien"])
    brut = json.dumps([dict(x) for x in main.db().execute("SELECT * FROM sbx_invites")])
    assert code not in brut and invitations.empreinte(code) in brut


def test_un_appareil_revoque_doit_etre_oublie_avant(banc, invit):
    alice_dev = store.appareil_par_did(main.db(), S.did_appareil(banc.pa))
    main.db().execute("UPDATE sbx_devices SET revoked_at=1 WHERE device_uuid=?", (alice_dev["device_uuid"],))
    b = json.loads(store.DEMANDES.read_text())
    for d in b["demandes"]:
        if d["cle_publique"] == banc.pa:
            d["etat"] = "refusee"
    store.DEMANDES.write_text(json.dumps(b))
    invit.prof._relit()
    r = main.cree_invitation(main.Invitation(role="guest", pseudo="nouveau"), main.moi(_req("tok-g")))
    with pytest.raises(HTTPException) as e:
        _rejoint(_code(r["lien"]), banc.ka, banc.pa)
    assert e.value.status_code == 409
    assert main.db().execute("SELECT count(*) FROM sbx_users WHERE pseudo='alice'").fetchone()[0] == 1
