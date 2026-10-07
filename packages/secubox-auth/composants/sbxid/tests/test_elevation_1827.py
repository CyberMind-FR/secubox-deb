# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""Élévation d'administration explicite depuis un appareil de confiance (#1827).

Décision du 2026-10-01 (#1802) : la clé de l'appareil remplace le mot de passe,
appareil DE CONFIANCE seulement, OTP hors du réseau local, session courte à
part ; la session SBX OS ordinaire n'est jamais une session d'administration.
"""
import json
import time

import jwt as pyjwt
import pyotp
import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric import utils as asym_utils
from fastapi import HTTPException
from starlette.requests import Request

from test_sbxid_module import banc  # noqa: F401
from secubox_core import sbxid as S
from api import main, store

SECRET = pyotp.random_base32()


def _signe(k, message: bytes) -> str:
    r, s = asym_utils.decode_dss_signature(k.sign(message, ec.ECDSA(hashes.SHA256())))
    return (r.to_bytes(32, "big") + s.to_bytes(32, "big")).hex()


def _req(tok, lan=True):
    h = [(b"authorization", f"Bearer {tok}".encode()), (b"user-agent", b"Pixel test")]
    if lan:
        h.append((b"x-secubox-lan", b"1"))
    return Request({"type": "http", "method": "POST", "path": "/", "headers": h,
                    "client": ("192.168.1.50", 5000)})


@pytest.fixture
def elev(banc, monkeypatch, tmp_path):
    monkeypatch.setenv("SECUBOX_AUTH_SESSIONS", str(tmp_path / "sessions.json"))
    monkeypatch.setenv("SECUBOX_TOTP_REPLAY_PATH", str(tmp_path / "totp-replay.json"))
    monkeypatch.setenv("SECUBOX_AUTH_REGLAGES", str(tmp_path / "reglages.json"))
    monkeypatch.setenv("SECUBOX_JWT_SECRET", "banc-1827-" + "x" * 32)
    systeme = {"admin": {"role": "admin", "enabled": True},
               "gk2": {"role": "admin", "enabled": True, "totp": {"enabled": True, "secret": SECRET}},
               "operator": {"role": "operator", "enabled": True}}
    monkeypatch.setattr(main.user_store, "get_user", lambda s: systeme.get(s))
    for nom in ("_DEFIS_ELEV", "_BONS_ELEV", "_ECHECS_OTP"):
        monkeypatch.setattr(main, nom, {})
    jetons = {"tok-g": {"sub": "gk2", "jti": "jti-g"}, "tok-g2": {"sub": "gk2", "jti": "jti-g2"},
              "tok-a": {"sub": "sbx-" + S.empreinte_cle(banc.pa)[:12], "jti": "zz"},
              "tok-adm": {"sub": "admin", "jti": "portail"},
              "tok-lien": {"sub": "gk2", "jti": "jti-g", "plafond": "guest"}}
    monkeypatch.setattr(main._auth, "_validate_token", lambda t: jetons.get(t))
    # Une seconde session du MÊME appareil (pour le défi d'une autre session).
    b = json.loads(store.DEMANDES.read_text())
    b["demandes"][0]["jtis"].append("jti-g2")
    store.DEMANDES.write_text(json.dumps(b))
    main._rafraichit()
    c = main.db()
    g = c.execute("SELECT user_uuid FROM sbx_users WHERE pseudo='gandalf'").fetchone()[0]
    c.execute("UPDATE sbx_devices SET trust_level='trusted' WHERE did=?", (S.did_appareil(banc.pg),))
    banc.g, banc.systeme, banc.tmp = g, systeme, tmp_path
    return banc


def _eleve(banc, tok="tok-g", lan=True, otp=None, cle=None):
    req = _req(tok, lan)
    ctx = main.moi(req)
    d = main.elevation_defi(req, None, ctx)
    sig = _signe(cle or banc.kg, bytes.fromhex(d["message_hex"]))
    return d, main.elevation(main.Elevation(defi=d["defi"], signature=sig, otp=otp), req, main.moi(req))


# ── Le lien personne ↔ compte système ────────────────────────────────────────

def test_lien_seme_depuis_le_rattachement(elev):
    c = main.db()
    assert store.comptes_systeme_de(c, elev.g) == ["gk2"]
    alice = c.execute("SELECT user_uuid FROM sbx_users WHERE pseudo='alice'").fetchone()[0]
    assert store.comptes_systeme_de(c, alice) == []
    assert store.seme_liens_systeme(c, main._sf.compte_admin_actif) == 0        # idempotent


def test_le_lien_ne_se_pose_que_par_un_administrateur_systeme(elev):
    c = main.db()
    alice = c.execute("SELECT user_uuid FROM sbx_users WHERE pseudo='alice'").fetchone()[0]
    with pytest.raises(HTTPException) as e:                     # session d'appareil
        main.lie_compte_systeme(alice, main.CompteSysteme(compte="admin"), _req("tok-a"))
    assert e.value.status_code == 403
    with pytest.raises(HTTPException) as e:                     # session bornée
        main.lie_compte_systeme(alice, main.CompteSysteme(compte="admin"), _req("tok-lien"))
    assert e.value.status_code == 403
    r = main.lie_compte_systeme(alice, main.CompteSysteme(compte="admin"), _req("tok-adm"))
    assert r["comptes"] == ["admin"]
    with pytest.raises(HTTPException) as e:                     # gk2 est déjà à gandalf
        main.lie_compte_systeme(alice, main.CompteSysteme(compte="gk2"), _req("tok-adm"))
    assert e.value.status_code == 409
    with pytest.raises(HTTPException) as e:                     # pas un compte d'administration
        main.lie_compte_systeme(alice, main.CompteSysteme(compte="operator"), _req("tok-adm"))
    assert e.value.status_code == 409
    assert main.delie_compte_systeme(alice, "admin", _req("tok-adm"))["comptes"] == []


def test_relier_un_compte_existant_ne_cree_jamais_de_lien_systeme(elev):
    from api import comptes
    c = main.db()
    alice = c.execute("SELECT user_uuid FROM sbx_users WHERE pseudo='alice'").fetchone()[0]
    with pytest.raises(comptes.Refus):
        comptes.lie_existant(c, alice, "systeme", "admin")


# ── L'élévation ──────────────────────────────────────────────────────────────

def test_sur_le_lan_la_cle_suffit(elev):
    e = main.elevation_etat(_req("tok-g"), main.moi(_req("tok-g")))
    assert e["possible"] and e["compte"] == "gk2" and e["otp_requis"] is False
    d, r = _eleve(elev)
    assert d["otp_requis"] is False and r["ok"] and r["compte"] == "gk2"
    assert r["url"].endswith("/login.html#elevation=" + r["bon"])
    j = main.elevation_echange(main.Bon(bon=r["bon"]))
    p = pyjwt.decode(j["access_token"], options={"verify_signature": False})
    assert p["sub"] == "gk2" and "plafond" not in p
    assert p["exp"] - time.time() <= main.ELEVATION_MAX_S + 5
    # La session d'administration est INSCRITE au registre (sinon refusée partout).
    lignes = json.loads((elev.tmp / "sessions.json").read_text())
    assert any(x["id"] == p["jti"] and x["username"] == "gk2" for x in lignes)
    # Le bon ne sert qu'une fois.
    with pytest.raises(HTTPException) as x:
        main.elevation_echange(main.Bon(bon=r["bon"]))
    assert x.value.status_code == 410
    assert any(ev["event"] == "admin.elevation" for ev in main.journal(main.exige_admin(_req("tok-g")))["evenements"])


def test_hors_du_lan_l_otp_est_exige_et_ne_sert_qu_une_fois(elev):
    with pytest.raises(HTTPException) as e:
        _eleve(elev, lan=False)
    assert e.value.status_code == 401
    with pytest.raises(HTTPException) as e:
        _eleve(elev, lan=False, otp="000000" if pyotp.TOTP(SECRET).now() != "000000" else "111111")
    assert e.value.status_code == 401
    code = pyotp.TOTP(SECRET).now()
    d, r = _eleve(elev, lan=False, otp=code)
    assert d["otp_requis"] is True and r["ok"]
    with pytest.raises(HTTPException) as e:                     # rejeu du même code
        _eleve(elev, lan=False, otp=code)
    assert e.value.status_code == 401


def test_otp_lan_obligatoire_s_applique(elev):
    (elev.tmp / "reglages.json").write_text(json.dumps({"otp_lan": "obligatoire"}))
    assert main.elevation_etat(_req("tok-g"), main.moi(_req("tok-g")))["otp_requis"] is True
    with pytest.raises(HTTPException) as e:
        _eleve(elev)
    assert e.value.status_code == 401


def test_trop_d_essais_otp_bride(elev):
    for _ in range(main.ECHECS_OTP_MAX):
        with pytest.raises(HTTPException):
            _eleve(elev, lan=False, otp="999999" if pyotp.TOTP(SECRET).now() != "999999" else "888888")
    with pytest.raises(HTTPException) as e:
        _eleve(elev, lan=False, otp=pyotp.TOTP(SECRET).now())
    assert e.value.status_code == 429


def test_appareil_sans_certificat_refuse(elev):
    main.db().execute("UPDATE sbx_devices SET trust_level='verified'")
    e = main.elevation_etat(_req("tok-g"), main.moi(_req("tok-g")))
    assert not e["possible"] and "certificat" in e["motif"]
    with pytest.raises(HTTPException) as x:
        _eleve(elev)
    assert x.value.status_code == 409


def test_sans_lien_pas_d_elevation(elev):
    main.db().execute("UPDATE sbx_devices SET trust_level='trusted'")
    with pytest.raises(HTTPException) as e:
        _eleve(elev, tok="tok-a", cle=elev.ka)
    assert e.value.status_code == 403 and "Aucun compte" in e.value.detail


def test_session_bornee_refusee(elev):
    with pytest.raises(HTTPException) as e:
        main.elevation_defi(_req("tok-lien"), None, main.moi(_req("tok-lien")))
    assert e.value.status_code == 403


def test_signature_d_une_autre_cle_refusee_et_defi_consomme(elev):
    req = _req("tok-g")
    d = main.elevation_defi(req, None, main.moi(req))
    faux = _signe(elev.ka, bytes.fromhex(d["message_hex"]))
    with pytest.raises(HTTPException) as e:
        main.elevation(main.Elevation(defi=d["defi"], signature=faux), req, main.moi(req))
    assert e.value.status_code == 422
    vrai = _signe(elev.kg, bytes.fromhex(d["message_hex"]))
    with pytest.raises(HTTPException) as e:                     # usage unique, même raté
        main.elevation(main.Elevation(defi=d["defi"], signature=vrai), req, main.moi(req))
    assert e.value.status_code == 410


def test_defi_d_une_autre_session_refuse(elev):
    r1 = _req("tok-g")
    d = main.elevation_defi(r1, None, main.moi(r1))
    r2 = _req("tok-g2")                                         # même appareil, autre session
    sig = _signe(elev.kg, bytes.fromhex(d["message_hex"]))
    with pytest.raises(HTTPException) as e:
        main.elevation(main.Elevation(defi=d["defi"], signature=sig), r2, main.moi(r2))
    assert e.value.status_code == 410


def test_compte_ferme_entre_temps(elev):
    req = _req("tok-g")
    d = main.elevation_defi(req, None, main.moi(req))
    elev.systeme["gk2"]["enabled"] = False
    sig = _signe(elev.kg, bytes.fromhex(d["message_hex"]))
    with pytest.raises(HTTPException) as e:
        main.elevation(main.Elevation(defi=d["defi"], signature=sig), req, main.moi(req))
    assert e.value.status_code == 403


def test_bon_expire(elev, monkeypatch):
    _, r = _eleve(elev)
    for v in main._BONS_ELEV.values():
        v["expire"] = time.time() - 1
    with pytest.raises(HTTPException) as e:
        main.elevation_echange(main.Bon(bon=r["bon"]))
    assert e.value.status_code == 410


def test_la_session_ordinaire_reste_ordinaire(elev):
    """L'élévation ne touche pas au cookie ni à la session de l'appareil."""
    req = _req("tok-g")
    _, r = _eleve(elev)
    assert "set-cookie" not in json.dumps(r).lower() and "access_token" not in r
