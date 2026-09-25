# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""SBX Identity Manager v0.1 (#1422) : import, qui-appelle, admin, certificat réel."""
import json
import types
import uuid

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from fastapi import HTTPException
from starlette.requests import Request

from secubox_core import sbxid as S
from api import main, store

GRAINE = "44" * 32


def _cle():
    k = ec.generate_private_key(ec.SECP256R1())
    return k, k.public_key().public_bytes(serialization.Encoding.X962,
                                          serialization.PublicFormat.UncompressedPoint).hex()


@pytest.fixture
def banc(tmp_path, monkeypatch):
    kg, pg = _cle()        # iPhone de Gérald, rattaché à gk2
    ka, pa = _cle()        # appareil d'alice, non rattaché, profil user
    kx, px = _cle()        # appareil révoqué
    demandes = {"demandes": [
        {"did": "did:sbx:x", "cle_publique": pg, "nom": "Gérald", "appareil": "iPhone iOS 17", "etat": "acceptee",
         "profil": "admin", "compte": "gk2", "jtis": ["jti-g"], "demandee_le": 1},
        {"did": "did:sbx:y", "cle_publique": pa, "nom": "Alice", "appareil": "Linux armv8", "etat": "acceptee",
         "profil": "user", "compte": None, "jtis": ["jti-a"], "demandee_le": 2},
        {"did": "did:sbx:z", "cle_publique": px, "nom": "Ancien", "appareil": "Android", "etat": "refusee",
         "traitee_le": 5, "profil": None, "compte": None, "jtis": [], "demandee_le": 3},
        {"did": "did:sbx:w", "cle_publique": _cle()[1], "nom": "root", "appareil": "Mac", "etat": "en_attente"},
    ]}
    f = tmp_path / "demandes.json"
    f.write_text(json.dumps(demandes))
    k = tmp_path / "node.key"
    k.write_text(GRAINE)
    monkeypatch.setattr(store, "DB", tmp_path / "sbx.db")
    monkeypatch.setattr(store, "DEMANDES", f)
    monkeypatch.setattr(main, "NODE_KEY", k)
    monkeypatch.setattr(main, "_DB", None)
    monkeypatch.setattr(main._cap, "SBX_DB", tmp_path / "sbx.db")
    monkeypatch.setattr(main._cap, "DEMANDES", f)
    sessions = {"tok-g": {"sub": "gk2", "jti": "jti-g"}, "tok-a": {"sub": "sbx-" + S.empreinte_cle(pa)[:12], "jti": "zz"},
                "tok-sys": {"sub": "operator", "jti": "j"}, "tok-adm": {"sub": "admin", "jti": "portail"},
                "tok-gpw": {"sub": "gk2", "jti": "portail"}}
    monkeypatch.setattr(main._auth, "_validate_token", lambda t: sessions.get(t))
    systeme = {"admin": {"role": "admin", "enabled": True}, "gk2": {"role": "admin", "enabled": True},
               "operator": {"role": "operator"}}
    monkeypatch.setattr(main.user_store, "get_user", lambda s: systeme.get(s))
    return types.SimpleNamespace(kg=kg, pg=pg, ka=ka, pa=pa)


def _req(tok):
    return Request({"type": "http", "method": "GET", "path": "/", "headers": [(b"authorization", f"Bearer {tok}".encode())]})


def test_import_et_correspondances(banc):
    c = main.db()
    pseudos = {r[0] for r in c.execute("SELECT pseudo FROM sbx_users")}
    assert pseudos == {"gandalf", "alice"}      # jamais gk2 ni root ; ni l'attente, ni un révoqué jamais rattaché
    g = c.execute("SELECT user_uuid FROM sbx_users WHERE pseudo='gandalf'").fetchone()[0]
    assert set(store.roles_de(c, g)) == {"sbx_operator", "moderator"}
    assert c.execute("SELECT count(*) FROM sbx_devices WHERE revoked_at IS NOT NULL").fetchone()[0] == 0
    assert store.importe_existant(c, "did:plc:" + "0" * 32)["appareils"] == 0     # idempotent


def test_pseudo_sans_accent_perdu(tmp_path):
    c = store.ouvre(tmp_path / "x.db")
    assert store._pseudo_libre(c, "Gérald") == "gerald"
    assert store._pseudo_libre(c, "root") == "root-sbx"


def test_qui_appelle(banc):
    g = main.route_moi(main.moi(_req("tok-g")))
    assert g["identite"]["pseudo"] == "gandalf" and "admin.users" in g["identite"]["capabilities"]
    a = main.route_moi(main.moi(_req("tok-a")))
    assert a["identite"]["pseudo"] == "alice" and "admin.users" not in a["identite"]["capabilities"]
    s = main.route_moi(main.moi(_req("tok-adm")))
    assert s["identite"] is None and s["systeme"]              # compte système : pas d'identité SBX OS
    with pytest.raises(HTTPException) as e:
        main.moi(_req("inconnu"))
    assert e.value.status_code == 401


def test_admin(banc):
    with pytest.raises(HTTPException) as e:
        main.exige_admin(_req("tok-a"))
    assert e.value.status_code == 403
    main.exige_admin(_req("tok-adm"))                          # l'exploitant système administre SBX OS
    ctx = main.exige_admin(_req("tok-g"))
    alice = next(p for p in main.personnes(ctx)["personnes"] if p["pseudo"] == "alice")
    p = main.fixe_roles(alice["user_uuid"], main.Roles(roles=["member", "beta_tester"]), ctx)
    assert "modules.experimental" in p["capabilities"]
    with pytest.raises(HTTPException):
        main.fixe_roles(alice["user_uuid"], main.Roles(roles=["root"]), ctx)
    # Pas d'auto-destitution pour un opérateur SBX OS sans compte système
    # (gandalf passe par gk2, compte système : lui peut se rattraper).
    main.fixe_roles(alice["user_uuid"], main.Roles(roles=["sbx_operator"]), ctx)
    ctx_a = main.exige_admin(_req("tok-a"))
    with pytest.raises(HTTPException) as e:
        main.fixe_roles(alice["user_uuid"], main.Roles(roles=["member"]), ctx_a)
    assert e.value.status_code == 409
    main.fixe_roles(alice["user_uuid"], main.Roles(roles=["member", "beta_tester"]), ctx)
    assert main.fixe_statut(alice["user_uuid"], main.Statut(status="suspended"), ctx)["capabilities"] == []
    assert any(e["event"] == "user.suspended" for e in main.journal(ctx)["evenements"])


def test_certificat_double_signature_reelle(banc):
    ctx = main.moi(_req("tok-g"))
    dev = ctx["device"]["device_uuid"]
    prep = main.prepare(dev, ctx)
    from api.main import S as _S
    sig = _S.signe_appareil(banc.kg, bytes.fromhex(prep["message_hex"]))   # ce que fait le navigateur
    out = main.signe(dev, main.Signature(serial=prep["serial"], sig_user=sig), ctx)
    assert "ecdsa-p256" in out["yaml"] and "ed25519" in out["yaml"]
    assert main.lit_certificat(dev, ctx)["certificat"]["sig_node"]
    with pytest.raises(HTTPException) as e:                     # le même préparatif ne sert qu'une fois
        main.signe(dev, main.Signature(serial=prep["serial"], sig_user=sig), ctx)
    assert e.value.status_code == 410


def test_certificat_signe_par_une_autre_cle_refuse(banc):
    ctx = main.moi(_req("tok-g"))
    dev = ctx["device"]["device_uuid"]
    prep = main.prepare(dev, ctx)
    faux = S.signe_appareil(banc.ka, bytes.fromhex(prep["message_hex"]))
    with pytest.raises(HTTPException) as e:
        main.signe(dev, main.Signature(serial=prep["serial"], sig_user=faux), ctx)
    assert e.value.status_code == 422


def test_on_ne_touche_pas_aux_appareils_d_autrui(banc):
    g = main.moi(_req("tok-g"))
    ctx_a = main.moi(_req("tok-a"))
    with pytest.raises(HTTPException) as e:
        main.renomme(g["device"]["device_uuid"], main.Renomme(nom="piraté"), ctx_a)
    assert e.value.status_code == 403


def test_admission_par_l_identity_manager(banc, tmp_path, monkeypatch):
    """Accepter = acces ouvre la porte (guest), sbxid donne le rôle SBX OS."""
    import asyncio
    import sys
    kn, pn = _cle()
    f = store.DEMANDES
    brut = json.loads(f.read_text())
    brut["demandes"].append({"did": "did:sbx:nouveau", "cle_publique": pn, "nom": "Chloé", "appareil": "iPad",
                             "etat": "en_attente", "demandee_le": 9, "jtis": []})
    f.write_text(json.dumps(brut))
    faux = types.ModuleType("faux_acces_main")

    class Verdict:
        def __init__(self, did, motif=""):
            self.did, self.motif = did, motif

    async def accepter(v, req):                  # ce que fait acces : etat → acceptee, profil guest
        b = json.loads(f.read_text())
        for d in b["demandes"]:
            if d["did"] == v.did:
                d.update(etat="acceptee", profil="guest", traitee_par=req.state.user)
        f.write_text(json.dumps(b))
        return {"ok": True, "lien": "https://hall/i/acces/?entree=XYZ"}

    async def refuser(v, req):
        return {"ok": True}
    faux.Verdict, faux.accepter, faux.refuser = Verdict, accepter, refuser
    faux.profileur, faux._coupe_sessions = (lambda: None), (lambda *a: None)
    monkeypatch.setitem(sys.modules, "faux_acces_main", faux)
    ctx = main.exige_admin(_req("tok-g"))
    att = main.demandes(ctx)["en_attente"]
    chloe = next(d for d in att if d["nom"] == "Chloé")
    assert len(chloe["empreinte"].split()) == 6
    req = _req("tok-g")
    out = asyncio.run(main.accepte("did:sbx:nouveau", main.Decision(role="member"), req, ctx))
    assert out["pseudo"] == "chloe" and out["roles"] == ["member"] and "entree=" in out["lien"]
    assert "Chloé" not in [d["nom"] for d in main.demandes(ctx)["en_attente"]]
    with pytest.raises(HTTPException):
        asyncio.run(main.accepte("did:sbx:nouveau", main.Decision(role="root"), req, ctx))


def test_session_gk2_par_mot_de_passe(banc):
    """#1452 : sans appareil, le compte gk2 désigne gandalf ; rien ne se signe pour autant."""
    m = main.route_moi(main.moi(_req("tok-gpw")))
    assert m["identite"]["pseudo"] == "gandalf" and m["par_compte"] == "gk2" and m["appareil_courant"] is None
    assert main.route_moi(main.moi(_req("tok-adm")))["identite"] is None   # admin : aucun appareil rattaché
    dev = m["appareils"][0]["device_uuid"]
    with pytest.raises(HTTPException) as e:
        main.prepare(dev, main.moi(_req("tok-gpw")))
    assert e.value.status_code == 409


def test_compte_bbs_d_appareil_lie_a_sa_personne(banc, tmp_path):
    """#1454 : le compte BBS sbx-<empreinte> d'un appareil de gandalf est gandalf."""
    import sqlite3
    b = tmp_path / "bbs.db"
    h = "sbx-" + S.empreinte_cle(banc.pg)[:12]
    x = sqlite3.connect(b)
    x.execute("CREATE TABLE users (handle TEXT)")
    x.executemany("INSERT INTO users VALUES (?)", [(h,), ("sbx-000000000000",), ("cedre83",)])
    x.commit(); x.close()
    c = main.db()
    assert store.lie_comptes_bbs_d_appareil(c, b) == 1
    assert store.lie_comptes_bbs_d_appareil(c, b) == 0            # idempotent
    liens = {(r[0], r[1]) for r in c.execute(
        "SELECT u.pseudo, l.app_id FROM sbx_app_links l JOIN sbx_users u USING(user_uuid) WHERE l.app='bbs'")}
    assert liens == {("gandalf", "gk2"), ("gandalf", h)}
    assert store.lie_comptes_bbs_d_appareil(c, tmp_path / "absent.db") == 0


# ── #1456 : personnes sans appareil, comptes de services, BBS lié ─────────
from api import comptes as CPT


def _faux_helper(monkeypatch, existants=()):
    appels, comptes_ = [], {k: "ancien" for k in existants}

    def h(d):
        appels.append(d)
        cle = (d["service"], d["user"])
        if d["action"] == "etat":
            return {"ok": True, "etat": {"existe": cle in comptes_}}
        if d["action"] == "creer":
            if d["service"] == "peertube":
                return {"ok": False, "erreur": "conteneur peertube arrêté", "disponible": False}
            comptes_[cle] = d["password"]
            return {"ok": True}
        if d["action"] == "reinitialiser":
            comptes_[cle] = d["password"]
            return {"ok": True}
        return {"ok": False, "erreur": "?"}
    monkeypatch.setattr(CPT, "helper", h)
    return appels, comptes_


def _fini(lance, uid, ctx):
    """#1458 : la route rend la main ; on relit le travail jusqu'au résultat (remis une fois)."""
    import time as _t
    assert lance == {"travail": "en_cours"}
    for _ in range(200):
        t = main.travail(uid, ctx)
        if t["etat"] != "en_cours":
            assert t["etat"] == "fini", t
            assert main.travail(uid, ctx) == {"etat": "aucun"}          # remis UNE fois
            return t
        _t.sleep(0.02)
    raise AssertionError("travail jamais fini")


def test_personne_sans_appareil_et_ses_comptes(banc, monkeypatch):
    appels, cpt = _faux_helper(monkeypatch)
    ctx = main.exige_admin(_req("tok-g"))
    p = main.cree_personne(main.NouvellePersonne(pseudo="Cedre83", email="cedre@exemple.org"), ctx)
    assert p["pseudo"] == "cedre83" and "member" in p["roles"]
    for mauvais in ("gk2", "a..b", "x y"):
        with pytest.raises(HTTPException):
            main.cree_personne(main.NouvellePersonne(pseudo=mauvais), ctx)
    with pytest.raises(HTTPException) as e:
        main.cree_personne(main.NouvellePersonne(pseudo="cedre83"), ctx)
    assert e.value.status_code == 409
    uid = p["user_uuid"]
    r = _fini(main.ouvre_comptes(uid, main.Services(services=["email", "nextcloud", "peertube"]), ctx), uid, ctx)
    pw = r["mot_de_passe"]
    assert r["services"]["email"] is True and r["services"]["nextcloud"] is True
    assert "arrêté" in r["services"]["peertube"]
    assert cpt[("email", "cedre83")] == cpt[("nextcloud", "cedre83")] == pw     # UN mot de passe
    assert r["adresse"] == "cedre83@secubox.in"
    # PeerTube plus tard : le nouveau mot de passe vaut pour TOUS
    monkeypatch.setattr(CPT, "helper", lambda d, _h=CPT.helper: {"ok": True} if d["service"] == "peertube"
                        and d["action"] == "creer" else _h(d))
    r2 = _fini(main.ouvre_comptes(uid, main.Services(services=["peertube"]), ctx), uid, ctx)
    assert r2["services"] == {"email": True, "nextcloud": True, "peertube": True}
    assert cpt[("email", "cedre83")] == cpt[("nextcloud", "cedre83")] == r2["mot_de_passe"] != pw
    # réinitialiser : un geste, tous les services
    r3 = _fini(main.reinitialise_comptes(uid, ctx), uid, ctx)
    assert set(r3["services"]) == {"email", "nextcloud", "peertube"} and r3["mot_de_passe"]
    assert all(x["action"] != "retirer" for x in appels)


def test_lier_le_compte_bbs_existant(banc, tmp_path, monkeypatch):
    import sqlite3
    b = tmp_path / "bbs.db"
    x = sqlite3.connect(b)
    x.execute("CREATE TABLE users (handle TEXT COLLATE NOCASE, disabled_at INTEGER)")
    x.executemany("INSERT INTO users VALUES (?,?)", [("Ani.skywalker", None), ("gk2", None), ("parti", 5)])
    x.commit(); x.close()
    monkeypatch.setattr(CPT, "BBS_DB", b)
    ctx = main.exige_admin(_req("tok-g"))
    ani = main.cree_personne(main.NouvellePersonne(pseudo="ani.skywalker"), ctx)["user_uuid"]
    assert main.lie_bbs(ani, main.LienBbs(handle="ani.skywalker"), ctx)["handle"] == "Ani.skywalker"
    for h, code in (("inconnu", 404), ("parti", 404), ("gk2", 409)):
        with pytest.raises(HTTPException) as e:
            main.lie_bbs(ani, main.LienBbs(handle=h), ctx)
        assert e.value.status_code == code, h
    autre = main.cree_personne(main.NouvellePersonne(pseudo="autre"), ctx)["user_uuid"]
    with pytest.raises(HTTPException) as e:                 # déjà lié à quelqu'un
        main.lie_bbs(autre, main.LienBbs(handle="Ani.skywalker"), ctx)
    assert e.value.status_code == 409
    main.delie(ani, "bbs", "Ani.skywalker", ctx)
    assert CPT.liens(main.db(), ani) == {}


def test_admission_rattachee_a_une_personne_existante(banc, monkeypatch):
    """Le téléphone de cedre, admis, devient un appareil de cedre83 — pas une nouvelle personne."""
    import asyncio
    import sys
    kn, pn = _cle()
    f = store.DEMANDES
    brut = json.loads(f.read_text())
    brut["demandes"].append({"did": "did:sbx:tel", "cle_publique": pn, "nom": "Cèdre", "appareil": "Android",
                             "etat": "en_attente", "demandee_le": 9, "jtis": []})
    f.write_text(json.dumps(brut))
    faux = types.ModuleType("faux_acces_main")

    class Verdict:
        def __init__(self, did, motif=""):
            self.did, self.motif = did, motif

    async def accepter(v, req):
        b = json.loads(f.read_text())
        for d in b["demandes"]:
            if d["did"] == v.did:
                d.update(etat="acceptee", profil="guest")
        f.write_text(json.dumps(b))
        return {"ok": True, "lien": ""}
    faux.Verdict, faux.accepter, faux.refuser = Verdict, accepter, accepter
    faux.profileur, faux._coupe_sessions = (lambda: None), (lambda *a: None)
    monkeypatch.setitem(sys.modules, "faux_acces_main", faux)
    ctx = main.exige_admin(_req("tok-g"))
    cedre = main.cree_personne(main.NouvellePersonne(pseudo="cedre83", role="member"), ctx)["user_uuid"]
    out = asyncio.run(main.accepte("did:sbx:tel", main.Decision(role="guest", personne=cedre), _req("tok-g"), ctx))
    assert out["pseudo"] == "cedre83"
    c = main.db()
    assert [a["name"] for a in store.appareils_de(c, cedre)] == ["Android"]
    assert store.roles_de(c, cedre) == ["member"]                    # ses rôles, pas « guest »
    assert not c.execute("SELECT 1 FROM sbx_users WHERE pseudo='cedre'").fetchone()   # pas de fantôme
