# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Exécuteur des réponses `ai-ban` (#3723, tâche 7) : client signé, exécution, rapprochement, suspension,
approbations et routes.

Le gk2 simulé est une application FastAPI de test qui sert `/ai/*` derrière la VRAIE garde
`secubox_core.compte_service` (clés publiques posées dans un arbre temporaire, audience `gk2`, mémoire de rejeu
neuve) et valide chaque corps par les VRAIS modèles Pydantic de gk2 (`gestes_ia.py`, chargé par chemin). Aucun réseau.
"""
import asyncio
import importlib.util
import json
import os
import re
import secrets
import sys
import threading
import time
import tomllib
from datetime import datetime, timedelta, timezone
from pathlib import Path

import httpx
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi import Depends, FastAPI, HTTPException, Request

from secubox_core import auth
from secubox_core import compte_service as cs
from veille import base, decisions, executeur, politiques
from veille.client import ClientGk2, ErreurGk2
from veille.regles import iso
from veille.service import Veille

PAQUET = Path(__file__).resolve().parents[1]
RACINE = PAQUET.parents[1]
GESTES_IA = RACINE / "packages" / "secubox-waf-ng" / "composants" / "waf" / "api" / "gestes_ia.py"
POLITIQUES = politiques.valider(tomllib.loads((PAQUET / "conf" / "politiques.toml.example").read_text("utf-8")))
A, B, C = "45.83.64.10", "45.83.64.11", "45.83.65.12"
TABLE = {n: (f"/ai/{r}", f"/ai/{r}") for n, r in (("ai_etat", "etat"), ("ai_ban", "ban"), ("ai_unban", "unban"),
                                                   ("ai_prolonger", "prolonger"), ("ai_limiter", "limiter"),
                                                   ("ai_leurre", "leurre"), ("ai_partager", "partager"))}


def _charger_gestes_ia():
    spec = importlib.util.spec_from_file_location("gk2_gestes_ia_3723", GESTES_IA)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod                    # annotations différées : les modèles s'y résolvent
    spec.loader.exec_module(mod)
    return mod


G = _charger_gestes_ia()
MODELES = {"ban": G.GesteBan, "unban": G.GesteAnnuler, "prolonger": G.GesteProlonger, "limiter": G.GesteLimiter,
           "leurre": G.GesteLeurre, "partager": G.GestePartager}
TYPES = {"limiter": "limite", "leurre": "leurre", "partager": "partage"}


def _paire():
    cle = Ed25519PrivateKey.generate()
    prive = cle.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                              serialization.NoEncryption())
    publique = cle.public_key().public_bytes(serialization.Encoding.PEM,
                                             serialization.PublicFormat.SubjectPublicKeyInfo)
    return prive, publique


def _poser(tmp_path, compte, publique):
    dossier = tmp_path / "comptes" / compte
    dossier.mkdir(parents=True, exist_ok=True)
    os.chmod(tmp_path / "comptes", 0o755)
    os.chmod(dossier, 0o755)
    f = dossier / f"{cs.empreinte(publique)}.pub"
    f.write_bytes(publique)
    os.chmod(f, 0o644)


class Gk2:
    """gk2 simulé : journal des gestes en mémoire, réponses forcées, comptage des appels."""

    def __init__(self):
        self.journal = {}
        self.appels = []
        self.forcer = []
        self.utilisateurs = []
        self.sade_mode = "active"
        self.app = FastAPI()

        def actifs(type_):
            m = int(time.time())
            return [{"id": i, "cible": e["cible"], "fin": e["fin"], "mode": e.get("mode", "auto")}
                    for i, e in sorted(self.journal.items())
                    if e["type"] == type_ and not e.get("annule") and e["fin"] > m]

        @self.app.get("/ai/etat")
        async def etat(user=Depends(G.require_ai_etat)):       # la VRAIE garde : ai-lecture OU ai-ban (#3720)
            return {"actifs": actifs("ban"), "limites": actifs("limite"), "leurres": actifs("leurre"),
                    "partages": actifs("partage"), "sade_mode": self.sade_mode,
                    "plafonds_par_geste": {g: {"heure": p["heure"], "jour": p["jour"], "restant_heure": p["heure"],
                                               "restant_jour": p["jour"]} for g, p in G.PLAFONDS_PAR_GESTE.items()}}

        for nom in MODELES:
            self.app.post(f"/ai/{'unban' if nom == 'unban' else nom}")(self._route(nom))

    def _route(self, nom):
        async def route(request: Request, user=Depends(cs.require_ai_ban)):
            corps = await request.body()
            geste = MODELES[nom].model_validate_json(corps)        # le VRAI contrat de gk2
            self.appels.append((nom, json.loads(corps)))
            self.utilisateurs.append(user)
            if self.forcer:
                statut, motif = self.forcer.pop(0)
                raise HTTPException(statut, detail={"motif": motif})
            m = int(time.time())
            if nom == "unban":
                e = self.journal.get(geste.id)
                if e is None:
                    raise HTTPException(404, detail={"motif": "inconnu"})
                e["annule"] = True
                return {"id": geste.id, "etat": "annule"}
            if nom == "prolonger":
                e = self.journal.get(geste.id)
                if e is None or e["type"] != "ban" or e.get("annule") or e["fin"] <= m:
                    raise HTTPException(409, detail={"motif": "inconnu"})
                if m + geste.duree_s < e["fin"]:
                    raise HTTPException(409, detail={"motif": "raccourcit"})
                e["fin"] = m + geste.duree_s
                return {"id": geste.id, "cible": e["cible"], "fin": e["fin"], "audit": secrets.token_hex(16)}
            type_ = TYPES.get(nom, "ban")
            if any(e["cible"] == geste.cible and e["type"] == type_ and not e.get("annule") and e["fin"] > m
                   for e in self.journal.values()):
                raise HTTPException(409, detail={"motif": "deja_actif"})
            ident = secrets.token_hex(16)
            self.journal[ident] = {"type": type_, "cible": geste.cible, "fin": m + geste.duree_s,
                                   "mode": getattr(geste, "mode", "auto")}
            rep = {"id": ident, "cible": geste.cible, "fin": m + geste.duree_s, "audit": ident}
            if nom == "ban":
                rep["duree_s"] = geste.duree_s
            return rep
        return route


class Transport(httpx.AsyncBaseTransport):
    """ASGI vers le gk2 simulé ; `couper` = 'avant' (rien n'arrive) ou 'apres' (gk2 a fait, la réponse se perd)."""

    def __init__(self, app):
        self.asgi = httpx.ASGITransport(app=app)
        self.couper = None
        self.requetes = []

    async def handle_async_request(self, request):
        self.requetes.append((request.method, request.url.path, request.headers.get("authorization"),
                              request.content))
        if self.couper == "avant" and request.method == "POST":
            raise httpx.ConnectError("coupé")
        r = await self.asgi.handle_async_request(request)
        if self.couper == "apres" and request.method == "POST":
            await r.aread()
            raise httpx.ReadTimeout("coupé")
        return r


@pytest.fixture
def banc(tmp_path, monkeypatch):
    monkeypatch.setattr(cs, "DOSSIER_COMPTES_SERVICE", str(tmp_path / "comptes"))
    monkeypatch.setattr(auth, "_proprietaire_attendu", lambda chemin: os.getuid())
    monkeypatch.setattr(auth, "nom_box_locale", lambda: "gk2")
    monkeypatch.setattr(auth, "AUDIT_PILOTAGE", str(tmp_path / "audit-gk2.log"))
    monkeypatch.setattr(cs, "_rejeu", cs._Rejeu())
    monkeypatch.setattr(cs, "_cache_cles", {})
    monkeypatch.setattr(cs, "_derniers_refus", {})
    monkeypatch.setattr(cs, "_minuterie", {"active": None})
    monkeypatch.setattr(cs, "_armer_minuterie", lambda: None)
    monkeypatch.setattr(cs, "_DEMARRAGE", 0.0)
    ban_prive, ban_pub = _paire()
    lec_prive, lec_pub = _paire()
    _poser(tmp_path, "ai-ban", ban_pub)
    _poser(tmp_path, "ai-lecture", lec_pub)
    gk2 = Gk2()
    t = Transport(gk2.app)
    db = base.ouvrir(tmp_path / "veille.db")

    class B:
        pass
    b = B()
    b.gk2, b.transport, b.db, b.tmp = gk2, t, db, tmp_path
    b.ban_prive, b.ban_pub, b.lec_prive = ban_prive, ban_pub, lec_prive
    b.client = ClientGk2("http://gk2", "gk2", lec_prive, TABLE, transport=t, cle_ban=ban_prive)
    b.lignes = []
    b.journal = lambda ev, det: b.lignes.append((ev, det)) or True
    yield b
    db.close()


def _maintenant():
    return datetime.now(timezone.utc)


def _dossier(db, did, gravite="high", etapes=1):
    db.execute("INSERT OR IGNORE INTO dossiers(id, cle, type, gravite, etapes_json, premiere_vue, derniere_vue, maj_le)"
               " VALUES (?, ?, 'acteur', ?, ?, 'a', 'b', 'c')",
               (did, did, gravite, json.dumps([{"etape": f"e{i}", "preuves": []} for i in range(etapes)])))
    return did


def _prop(db, geste="ban", cible=A, mode="auto", etat="proposee", duree=86400, reference=None, expire_s=3600,
          dossier=None, cree=None, version=1):
    pid = secrets.token_hex(8)
    m = cree or _maintenant()
    db.execute("INSERT INTO propositions(id, version, dossier_id, geste, cible, duree_s, mode, niveau, reference, "
               "politique, motif, etat, expire_le, cree_le, maj_le) VALUES (?, ?, ?, ?, ?, ?, ?, 'usager', ?, ?, "
               "'riposte usager : ban 96 h', ?, ?, ?, ?)",
               (pid, version, dossier, geste, cible, duree, mode, reference, f"gestes.{geste}", etat,
                iso(_maintenant() + timedelta(seconds=expire_s)), iso(m), iso(m)))
    return pid


def _tour(b, pol=POLITIQUES, client="defaut", maintenant=None):
    v = Veille(b.db, _maintenant, [])
    asyncio.run(executeur.executer(v, b.client if client == "defaut" else client, maintenant or _maintenant(),
                                   politiques=pol, journal=b.journal))


def _etat(db, pid):
    return db.execute("SELECT etat FROM propositions WHERE id = ?", (pid,)).fetchone()[0]


def _action(db, pid):
    r = db.execute("SELECT etat, code_http, motif, id_gk2, jti, cle, mode, id_cible_gk2 FROM actions "
                   "WHERE proposition_id = ?", (pid,)).fetchone()
    return None if r is None else dict(zip(("etat", "code", "motif", "id_gk2", "jti", "cle", "mode", "id_cible"), r))


# ── client signé contre la garde réelle ──

def test_jeton_portee_aud_corps_jti_valides_contre_garde_reelle(banc):
    pid = _prop(banc.db, mode="clic", etat="approuvee")
    _tour(banc)
    assert _etat(banc.db, pid) == "faite"
    a = _action(banc.db, pid)
    u = banc.gk2.utilisateurs[-1]
    # la garde réelle a vérifié sujet, portée, audience, corps et consommé CE jti ; la clé est celle de ai-ban
    assert u["sub"] == "ai-ban" and u["jti"] == a["jti"] and u["cle"] == a["cle"] == cs.empreinte(banc.ban_pub)
    assert a["id_gk2"] and re.fullmatch(r"[0-9a-f]{32}", a["id_gk2"]) and a["code"] == 200 and a["mode"] == "clic"
    _, corps = banc.gk2.appels[-1]
    assert corps["geste"] == "ban" and corps["cible"] == A and corps["mode"] == "clic"
    assert re.fullmatch(r"[A-Za-z0-9._-]{1,64}", corps["conseil"])

    # audience d'une autre box : 403 ; jeton signé par la clé de LECTURE pour un geste : 401 (clé inconnue du compte)
    autre = ClientGk2("http://gk2", "gk3", banc.lec_prive, TABLE, transport=banc.transport, cle_ban=banc.ban_prive)
    with pytest.raises(ErreurGk2) as e:
        asyncio.run(autre.post("ai_limiter", {"geste": "limiter", "cible": B, "duree_s": 3600, "conseil": "t"}))
    assert e.value.code == 403
    mauvais = ClientGk2("http://gk2", "gk2", banc.lec_prive, TABLE, transport=banc.transport, cle_ban=banc.lec_prive)
    with pytest.raises(ErreurGk2) as e:
        asyncio.run(mauvais.post("ai_limiter", {"geste": "limiter", "cible": B, "duree_s": 3600, "conseil": "t"}))
    assert e.value.code == 401
    # corps changé après la signature (jeton neuf, jti jamais vu) : 401 sur l'empreinte du corps
    signe = json.dumps({"geste": "limiter", "cible": B, "duree_s": 3600, "conseil": "t"}).encode()
    jeton = cs.frapper_jeton(banc.ban_prive, "ai-ban", aud="gk2", corps=signe, maintenant=time.time())
    falsifie = signe.replace(B.encode(), C.encode())

    async def envoyer():
        async with httpx.AsyncClient(transport=banc.transport) as c:
            return await c.post("http://gk2/ai/limiter", content=falsifie,
                                headers={"Authorization": f"Bearer {jeton}", "Content-Type": "application/json"})
    r = asyncio.run(envoyer())
    assert r.status_code == 401 and "corps" in r.text
    # aucun geste hors du catalogue, aucun POST signé ai-lecture
    with pytest.raises(ValueError):
        asyncio.run(banc.client.post("ai_etat", {}))
    with pytest.raises(ValueError):
        asyncio.run(banc.client.post("menaces_flux", {}))


def test_jeton_rejoue_refuse_par_gk2(banc):
    pid = _prop(banc.db, mode="clic", etat="approuvee")
    _tour(banc)
    assert _etat(banc.db, pid) == "faite"
    methode, chemin, entete, contenu = next(r for r in banc.transport.requetes if r[0] == "POST")

    async def rejouer():
        async with httpx.AsyncClient(transport=banc.transport) as c:
            return await c.post(f"http://gk2{chemin}", content=contenu,
                                headers={"Authorization": entete, "Content-Type": "application/json"})
    r = asyncio.run(rejouer())
    assert r.status_code == 401 and "rejeu" in r.text
    assert len(banc.gk2.journal) == 1


def test_audit_sans_jeton_ni_cle(banc):
    pid = _prop(banc.db, mode="auto")
    _tour(banc)
    assert _etat(banc.db, pid) == "faite"
    jetons = [r[2].split(" ", 1)[1] for r in banc.transport.requetes if r[2]]
    assert jetons
    textes = [json.dumps(banc.lignes, ensure_ascii=False)]
    textes += [json.dumps(r) for r in banc.db.execute("SELECT * FROM audit_chaine").fetchall()]
    textes += [json.dumps(r) for r in banc.db.execute("SELECT * FROM actions").fetchall()]
    tout = "\n".join(textes)
    for j in jetons:
        assert j not in tout and j.split(".")[2] not in tout
    assert "PRIVATE KEY" not in tout and banc.ban_prive.decode().splitlines()[1] not in tout
    evenements = [ev for ev, _ in banc.lignes]
    assert "ai-reponse-envoi" in evenements and "ai-reponse-gk2" in evenements
    envoi = next(d for ev, d in banc.lignes if ev == "ai-reponse-envoi")
    assert envoi["cle"] == cs.empreinte(banc.ban_pub)          # l'empreinte de la clé, jamais la clé
    ops = {o for (o,) in banc.db.execute("SELECT operation FROM audit_chaine")}
    assert {"reponse_envoi", "reponse_gk2"} <= ops


# ── exécution ──

def test_double_execution_impossible_apres_redemarrage(banc):
    pid = _prop(banc.db, mode="auto")
    _tour(banc)
    assert _etat(banc.db, pid) == "faite" and len(banc.gk2.appels) == 1
    _tour(banc)                                         # « redémarrage » : nouveau tour, même base
    assert len(banc.gk2.appels) == 1
    # même si l'état de la proposition était remis à « approuvee », l'unicité de l'action interdit un second envoi
    banc.db.execute("DROP INDEX idx_prop_vivante")
    banc.db.execute("UPDATE propositions SET etat = 'approuvee' WHERE id = ?", (pid,))
    _tour(banc)
    assert len(banc.gk2.appels) == 1
    assert banc.db.execute("SELECT COUNT(*) FROM actions WHERE proposition_id = ?", (pid,)).fetchone()[0] == 1


def test_envoi_interrompu_rapproche_jamais_rejoue(banc):
    pid = _prop(banc.db, mode="auto")
    banc.transport.couper = "apres"                     # gk2 a banni, la réponse se perd (arrêt en plein envoi)
    _tour(banc)
    assert _action(banc.db, pid)["etat"] == "envoi" and _etat(banc.db, pid) == "envoyee"
    autre = _prop(banc.db, cible=B, mode="auto")
    banc.transport.couper = None
    # moins de 90 s après l'envoi : la réponse peut encore arriver, on n'envoie rien d'autre et on ne rapproche pas
    _tour(banc, maintenant=_maintenant() + timedelta(seconds=30))
    assert _action(banc.db, pid)["etat"] == "envoi" and _action(banc.db, autre) is None
    # redémarrage : le rapprochement passe AVANT toute nouvelle tentative, et ne renvoie jamais la première
    _tour(banc, maintenant=_maintenant() + timedelta(seconds=100))
    a = _action(banc.db, pid)
    assert a["etat"] == "faite" and a["id_gk2"] in banc.gk2.journal and _etat(banc.db, pid) == "faite"
    assert [c["cible"] for _, c in banc.gk2.appels] == [A, B]           # A une seule fois
    assert _etat(banc.db, autre) == "faite"
    assert any(ev == "ai-reponse-rapprochee" for ev, _ in banc.lignes)

    # envoi perdu AVANT gk2 : rapproché « absent » → échec, jamais renvoyé
    p2 = _prop(banc.db, cible=C, mode="auto")
    banc.transport.couper = "avant"
    _tour(banc, maintenant=_maintenant() + timedelta(seconds=200))
    assert _action(banc.db, p2)["etat"] == "envoi"
    banc.transport.couper = None
    _tour(banc, maintenant=_maintenant() + timedelta(seconds=400))
    assert _action(banc.db, p2)["etat"] == "echec" and _etat(banc.db, p2) == "echec"
    assert [c["cible"] for _, c in banc.gk2.appels] == [A, B]


def test_rapprochement_impossible_bloque_tout_nouvel_envoi(banc, monkeypatch):
    pid = _prop(banc.db, mode="auto")
    banc.transport.couper = "apres"
    _tour(banc)
    banc.transport.couper = None
    autre = _prop(banc.db, cible=B, mode="auto")

    async def panne(*a, **k):
        raise ErreurGk2(None, "ConnectError")
    monkeypatch.setattr(banc.client, "get", panne)
    _tour(banc, maintenant=_maintenant() + timedelta(seconds=100))
    assert _action(banc.db, pid)["etat"] == "envoi" and _action(banc.db, autre) is None
    assert len(banc.gk2.appels) == 1


def test_proposition_expiree_non_executee(banc):
    p1 = _prop(banc.db, mode="auto", expire_s=-10)
    p2 = _prop(banc.db, cible=B, mode="clic", etat="approuvee", expire_s=-10)
    _tour(banc)
    assert _etat(banc.db, p1) == "expiree" and _etat(banc.db, p2) == "expiree"
    assert banc.gk2.appels == [] and _action(banc.db, p1) is None


def test_clic_non_approuve_jamais_execute(banc):
    pid = _prop(banc.db, mode="clic")
    _tour(banc)
    assert _etat(banc.db, pid) == "proposee" and banc.gk2.appels == []


def test_auto_suspendu_rien_d_office_clic_possible(banc):
    decisions.suspendre(banc.db, "admin", _maintenant())
    auto = _prop(banc.db, mode="auto")
    _tour(banc)
    assert _etat(banc.db, auto) == "proposee" and banc.gk2.appels == []
    # approuvée par un administrateur : envoyée en clic malgré la suspension
    decisions.decider(banc.db, auto, 1, "admin", "approuver", _maintenant())
    _tour(banc)
    assert _etat(banc.db, auto) == "faite" and banc.gk2.appels[-1][1]["mode"] == "clic"
    # la suspension de la politique a le même effet
    pol = politiques.valider({**tomllib.loads((PAQUET / "conf" / "politiques.toml.example").read_text("utf-8")),
                              "suspension": {"automatique_suspendu": True}})
    decisions.reprendre(banc.db, "admin", _maintenant())
    p2 = _prop(banc.db, cible=B, mode="auto")
    _tour(banc, pol=pol)
    assert _etat(banc.db, p2) == "proposee"


def test_trois_409_plafond_suspendent(banc):
    m = _maintenant()
    ids = [_prop(banc.db, cible=c, mode="auto", cree=m - timedelta(seconds=i)) for i, c in enumerate((A, B, C))]
    p4 = _prop(banc.db, cible="45.83.66.1", mode="auto", cree=m - timedelta(minutes=5))
    banc.gk2.forcer = [(409, "plafond_heure")] * 3
    _tour(banc)
    assert [_etat(banc.db, p) for p in ids] == ["refusee_gk2"] * 3
    assert {_action(banc.db, p)["motif"] for p in ids} == {"plafond_heure"}
    assert decisions.suspension(banc.db)["suspendu"] is True
    assert decisions.suspension(banc.db)["par"] == "secubox-ai-veille"
    assert _etat(banc.db, p4) == "proposee" and len(banc.gk2.appels) == 3   # rien d'office après la suspension
    assert any(ev == "veille-auto-suspendue" for ev, _ in banc.lignes)
    assert banc.db.execute("SELECT COUNT(*) FROM audit_chaine WHERE operation = 'veille-auto-suspendue'"
                           ).fetchone()[0] == 1
    # la suspension survit au redémarrage (veille.db), la reprise l'efface et s'audite
    _tour(banc)
    assert _etat(banc.db, p4) == "proposee"
    decisions.reprendre(banc.db, "admin", _maintenant())
    _tour(banc)
    assert _etat(banc.db, p4) == "faite"


def test_deux_409_plafond_ne_suspendent_pas(banc):
    m = _maintenant()
    ids = [_prop(banc.db, cible=c, mode="auto", cree=m - timedelta(seconds=i)) for i, c in enumerate((A, B))]
    banc.gk2.forcer = [(409, "plafond_jour"), (409, "protegee")]
    _tour(banc)
    assert decisions.suspension(banc.db)["suspendu"] is False
    assert [_action(banc.db, p)["motif"] for p in ids] == ["plafond_jour", "protegee"]


def test_503_suspend(banc):
    p1 = _prop(banc.db, cible=A, mode="auto")
    banc.gk2.forcer = [(503, "etat")]
    _tour(banc)
    a = _action(banc.db, p1)
    assert a["etat"] == "echec" and a["code"] == 503 and a["motif"] == "etat" and _etat(banc.db, p1) == "echec"
    s = decisions.suspension(banc.db)
    assert s["suspendu"] is True and s["motif"] == "503"


def test_ordre_gravite_etapes_recence_sous_plafond(banc):
    pol = politiques.valider({**tomllib.loads((PAQUET / "conf" / "politiques.toml.example").read_text("utf-8")),
                              "plafonds": {"ban": {"heure": 2, "jour": 400}}})
    m = _maintenant()
    faible = _prop(banc.db, cible=A, dossier=_dossier(banc.db, "d1", "medium", 3), cree=m)
    forte_ancienne = _prop(banc.db, cible=B, dossier=_dossier(banc.db, "d2", "critical", 1),
                           cree=m - timedelta(minutes=5))
    forte_etapes = _prop(banc.db, cible=C, dossier=_dossier(banc.db, "d3", "critical", 2),
                         cree=m - timedelta(minutes=9))
    _tour(banc, pol=pol)
    assert [c["cible"] for _, c in banc.gk2.appels] == [C, B]
    assert _etat(banc.db, faible) == "proposee"                       # plafond de gk3 atteint : attend
    assert _etat(banc.db, forte_ancienne) == _etat(banc.db, forte_etapes) == "faite"


def test_prolonger_et_unban_par_l_id_de_gk2(banc):
    ban = _prop(banc.db, mode="auto")
    _tour(banc)
    id_gk2 = _action(banc.db, ban)["id_gk2"]
    pro = _prop(banc.db, geste="prolonger", cible=A, duree=4 * 86400, reference=ban)
    _tour(banc)
    assert _etat(banc.db, pro) == "faite" and banc.gk2.appels[-1][1] == {
        "geste": "prolonger", "id": id_gk2, "duree_s": 4 * 86400, "conseil": banc.gk2.appels[-1][1]["conseil"],
        "motif": banc.gk2.appels[-1][1]["motif"], "mode": "auto"}
    assert _action(banc.db, pro)["id_cible"] == id_gk2
    lev = _prop(banc.db, geste="unban", cible=A, duree=None, reference=ban)
    _tour(banc)
    assert banc.gk2.appels[-1][1] == {"geste": "unban", "id": id_gk2}
    assert _etat(banc.db, lev) == "faite" and banc.gk2.journal[id_gk2]["annule"]


def test_reference_introuvable_echec_sans_envoi(banc):
    sans = _prop(banc.db, geste="prolonger", cible=A, duree=86400, reference=None)
    fausse = _prop(banc.db, geste="unban", cible=B, duree=None, reference="inexistante")
    _tour(banc)
    assert _etat(banc.db, sans) == _etat(banc.db, fausse) == "echec" and banc.gk2.appels == []
    assert any(d.get("motif") == "reference" for ev, d in banc.lignes if ev == "ai-reponse-echec")


def test_limiter_leurre_partager_formes_de_gk2(banc):
    _prop(banc.db, geste="limiter", cible="2a01:4f8:c0c:1::1", duree=6 * 3600)
    _prop(banc.db, geste="leurre", cible=B, duree=86400)
    _prop(banc.db, geste="partager", cible=C, duree=7 * 86400)
    _tour(banc)
    assert sorted(n for n, _ in banc.gk2.appels) == ["leurre", "limiter", "partager"]
    partage = next(c for n, c in banc.gk2.appels if n == "partager")
    assert re.fullmatch(G.FAMILLE_INDICE, partage["famille"]) and "motif" not in partage


def test_cle_absente_aucune_execution(banc):
    pid = _prop(banc.db, mode="auto")
    _tour(banc, client=None)
    assert _etat(banc.db, pid) == "proposee" and banc.gk2.appels == []
    assert json.loads(decisions.lire_etat(banc.db, "cle_ai_ban"))["etat"] == "absente"
    sans_ban = ClientGk2("http://gk2", "gk2", banc.lec_prive, TABLE, transport=banc.transport, cle_ban=None)
    _tour(banc, client=sans_ban)
    assert _etat(banc.db, pid) == "proposee" and banc.gk2.appels == []
    _tour(banc)
    assert json.loads(decisions.lire_etat(banc.db, "cle_ai_ban")) == {"etat": "presente",
                                                                     "empreinte": cs.empreinte(banc.ban_pub)}


def test_releve_ai_etat_garde_pour_la_console(banc):
    _tour(banc)
    rel = json.loads(decisions.lire_etat(banc.db, "ai_etat"))
    assert rel["sade_mode"] == "active" and rel["plafonds_par_geste"]["ban"]["restant_heure"] == 60


def test_relais_audit_des_decisions_de_l_api(banc):
    pid = _prop(banc.db, mode="clic")
    decisions.decider(banc.db, pid, 1, "admin", "refuser", _maintenant())
    decisions.suspendre(banc.db, "admin", _maintenant())
    _tour(banc)
    evs = [ev for ev, _ in banc.lignes]
    assert "ai-proposition-refusee" in evs and "veille-suspendue" in evs
    n = len(banc.lignes)
    _tour(banc)                                         # relais : une seule fois
    assert [ev for ev, _ in banc.lignes[n:] if ev in ("ai-proposition-refusee", "veille-suspendue")] == []


# ── approbations ──

def test_double_approbation_concurrente_une_seule_gagne(tmp_path):
    chemin = tmp_path / "veille.db"
    db = base.ouvrir(chemin)
    pid = _prop(db, mode="clic")
    db.close()
    barriere = threading.Barrier(2)
    issues = []

    def approuver(qui):
        c = base._connecter(chemin)
        barriere.wait()
        try:
            decisions.decider(c, pid, 1, qui, "approuver", _maintenant())
            issues.append("ok")
        except decisions.RefusDecision as e:
            issues.append(e.motif)
        finally:
            c.close()
    fils = [threading.Thread(target=approuver, args=(f"admin{i}",)) for i in range(2)]
    for f in fils:
        f.start()
    for f in fils:
        f.join()
    assert sorted(issues) == ["decidee", "ok"]
    db = base.ouvrir(chemin)
    assert db.execute("SELECT COUNT(*) FROM approbations WHERE proposition_id = ?", (pid,)).fetchone()[0] == 1
    assert _etat(db, pid) == "approuvee"
    db.close()


def test_version_changee_refuse_approbation(banc):
    pid = _prop(banc.db, mode="clic", version=2)
    with pytest.raises(decisions.RefusDecision) as e:
        decisions.decider(banc.db, pid, 1, "admin", "approuver", _maintenant())
    assert (e.value.statut, e.value.motif) == (409, "version")
    with pytest.raises(decisions.RefusDecision) as e:
        decisions.decider(banc.db, "absente", 1, "admin", "approuver", _maintenant())
    assert e.value.statut == 404
    exp = _prop(banc.db, cible=B, mode="clic", expire_s=-5)
    with pytest.raises(decisions.RefusDecision) as e:
        decisions.decider(banc.db, exp, 1, "admin", "refuser", _maintenant())
    assert e.value.motif == "expiree"
    decisions.decider(banc.db, pid, 2, "admin", "refuser", _maintenant())
    assert _etat(banc.db, pid) == "refusee"
    with pytest.raises(decisions.RefusDecision) as e:
        decisions.decider(banc.db, pid, 2, "admin", "approuver", _maintenant())
    assert e.value.motif == "decidee"


# ── routes de l'API ──

@pytest.fixture
def api(tmp_path, monkeypatch):
    from fastapi.testclient import TestClient
    from secubox_core.auth import require_jwt
    from api.main import app
    monkeypatch.setenv("SECUBOX_AI_ETAT", str(tmp_path))
    db = base.ouvrir(tmp_path / "veille.db")
    app.dependency_overrides[require_jwt] = lambda: {"sub": "admin"}
    try:
        yield TestClient(app), db
    finally:
        app.dependency_overrides.pop(require_jwt, None)
        db.close()


def test_routes_propositions_approbation_suspension(api):
    c, db = api
    pids = [_prop(db, cible=f"45.83.70.{i}", mode="clic", cree=_maintenant() - timedelta(seconds=i))
            for i in range(5)]
    r = c.get("/propositions", params={"limite": 2})
    assert r.status_code == 200 and [p["id"] for p in r.json()["propositions"]] == pids[:2]
    r2 = c.get("/propositions", params={"limite": 2, "curseur": r.json()["curseur"]})
    assert [p["id"] for p in r2.json()["propositions"]] == pids[2:4]
    assert c.get("/propositions", params={"limite": 501}).status_code == 422
    assert c.get(f"/propositions/{pids[0]}").json()["proposition"]["etat"] == "proposee"
    assert c.get("/propositions/inconnue").status_code == 404
    assert c.post(f"/propositions/{pids[0]}/approuver", json={"version": 2}).status_code == 409
    r = c.post(f"/propositions/{pids[0]}/approuver", json={"version": 1})
    assert r.status_code == 200 and r.json()["etat"] == "approuvee"
    assert c.post(f"/propositions/{pids[0]}/refuser", json={"version": 1}).status_code == 409
    assert c.post(f"/propositions/{pids[1]}/refuser", json={"version": "1"}).status_code == 422
    assert c.post(f"/propositions/{pids[1]}/refuser", json={"version": 1, "x": 1}).status_code == 422
    assert c.get("/actions").json()["actions"] == []
    assert c.get("/veille/etat").json()["suspension"]["suspendu"] is False
    assert c.post("/veille/suspendre").json()["suspension"]["suspendu"] is True
    e = c.get("/veille/etat").json()
    assert e["suspension"]["suspendu"] is True and e["suspension"]["par"] == "admin"
    assert "plafonds" in e and "cle_ai_ban" in e and "sade_mode" in e
    assert c.post("/veille/reprendre").json()["suspension"]["suspendu"] is False
    acteurs = {a for (a,) in db.execute("SELECT acteur FROM audit_chaine WHERE operation LIKE 'proposition_%' "
                                        "OR operation LIKE 'veille_%'")}
    assert acteurs == {"admin"}


def test_routes_sans_veille_db_503(tmp_path, monkeypatch):
    from fastapi.testclient import TestClient
    from secubox_core.auth import require_jwt
    from api.main import app
    monkeypatch.setenv("SECUBOX_AI_ETAT", str(tmp_path / "vide"))
    app.dependency_overrides[require_jwt] = lambda: {"sub": "admin"}
    try:
        c = TestClient(app)
        assert c.get("/propositions").status_code == 503
        assert c.post("/veille/suspendre").status_code == 503
        assert not (tmp_path / "vide" / "veille.db").exists()           # l'API ne crée jamais la base
    finally:
        app.dependency_overrides.pop(require_jwt, None)


def test_toute_route_est_gardee():
    from fastapi.routing import APIRoute
    from secubox_core.auth import require_jwt
    from api.main import app
    routes = {(m, r.path): r for r in app.routes if isinstance(r, APIRoute) for m in r.methods}
    attendues = {("GET", "/propositions"), ("GET", "/propositions/{pid}"), ("GET", "/actions"),
                 ("GET", "/veille/etat"), ("POST", "/propositions/{pid}/approuver"),
                 ("POST", "/propositions/{pid}/refuser"), ("POST", "/veille/suspendre"),
                 ("POST", "/veille/reprendre")}
    assert attendues <= set(routes)
    for cle, route in routes.items():
        if route.path == "/health":
            continue
        assert require_jwt in [d.call for d in route.dependant.dependencies], cle


def test_refus_sans_jeton():
    from fastapi.testclient import TestClient
    from api.main import app
    c = TestClient(app)
    assert c.post("/propositions/x/approuver", json={"version": 1}).status_code in (401, 403)
    assert c.post("/veille/reprendre").status_code in (401, 403)


# ── paquet : unité, profil, version ──

def test_unite_credentials_avec_repli_et_audit_en_ajout():
    texte = (PAQUET / "systemd" / "secubox-ai-veille.service").read_text(encoding="utf-8")
    code = "\n".join(x for x in texte.splitlines() if not x.lstrip().startswith("#"))
    for nom, fichier in (("ai-lecture", "ai-lecture.key"), ("ai-ban", "ai-ban.key")):
        assert f"LoadCredential={nom}:/etc/secubox/secrets/ai/{fichier}" in code
        assert f"SetCredential={nom}:absente" in code
    # le dossier (un montage lié du seul fichier resterait sur l'inode d'avant la rotation) ; AppArmor borne à
    # l'ajout dans audit.log seul
    assert re.search(r"^ReadWritePaths=-/var/log/secubox$", code, re.M)
    assert "ExecStartPre=+-/usr/sbin/secubox-aictl acl-audit" in code
    profil = (PAQUET / "apparmor" / "secubox-ai-veille").read_text(encoding="utf-8")
    pcode = "\n".join(x for x in profil.splitlines() if not x.lstrip().startswith("#"))
    assert "/run/credentials/secubox-ai-veille.service/ai-ban r," in pcode
    assert re.search(r"^\s*/var/log/secubox/audit\.log a,$", pcode, re.M)
    assert not re.search(r"/var/log/secubox/audit\.log [a-z]*w", pcode)
    assert [x.strip() for x in pcode.splitlines() if "/var/log" in x] == ["/var/log/secubox/audit.log a,"]
    api = (PAQUET / "apparmor" / "secubox-ai-api").read_text(encoding="utf-8")
    assert "ai-ban" not in "\n".join(x for x in api.splitlines() if not x.lstrip().startswith("#"))


def test_version_2_0_0():
    from api.main import VERSION
    assert VERSION == "2.0.0"                                          # #3725 : secubox-ai V2 (phases 4 à 7)
    assert (PAQUET / "debian" / "changelog").read_text(encoding="utf-8").startswith("secubox-ai (2.0.0-1~trixie1)")


def test_cle_lue_absente_ou_repli(tmp_path, monkeypatch):
    lire = executeur.lire_cle
    assert lire(None, "ai-ban") is None
    (tmp_path / "ai-ban").write_bytes(b"absente\n")
    assert lire(str(tmp_path), "ai-ban") is None
    prive, _ = _paire()
    (tmp_path / "ai-ban").write_bytes(prive)
    assert lire(str(tmp_path), "ai-ban") == prive
    assert lire(str(tmp_path), "ai-autre") is None


# ── secubox-aictl : clé ai-ban, suspension, ACL d'audit ──

from test_aictl_3583 import ctl, env  # noqa: E402,F401  (fixtures du contrôleur, environnement simulé)


def test_aictl_cle_ai_ban_generee_jamais_ecrasee(ctl, env, monkeypatch, capsys):  # noqa: F811
    cle = env.tmp / "secrets" / "ai" / "ai-ban.key"
    monkeypatch.setenv("SECUBOX_AI_CLE_BAN", str(cle))
    assert ctl.main(["cle-ai-ban", "generer"]) == 0
    sortie = capsys.readouterr().out
    assert sortie.startswith("-----BEGIN PUBLIC KEY-----") and "PRIVATE" not in sortie
    assert oct(cle.stat().st_mode & 0o777) == "0o600" and b"PRIVATE KEY" in cle.read_bytes()
    avant = cle.read_bytes()
    assert ctl.main(["cle-ai-ban", "generer"]) == 2 and cle.read_bytes() == avant
    assert ctl.main(["cle-ai-ban"]) == 2
    audit = env.audit.read_text()
    assert cs.empreinte(sortie.encode()) in audit and "PRIVATE" not in audit
    monkeypatch.setattr(ctl, "_root", lambda: False)
    assert ctl.main(["cle-ai-ban", "generer"]) == 2


def test_aictl_veille_suspendre_reprendre(ctl, env, capsys):  # noqa: F811
    assert ctl.main(["veille", "suspendre"]) == 1                  # pas de base : jamais créée par le contrôleur
    assert not (env.etat / "veille.db").exists()
    db = base.ouvrir(env.etat / "veille.db")
    assert ctl.main(["veille", "suspendre"]) == 0
    s = decisions.suspension(db)
    assert s["suspendu"] is True and s["par"].startswith("aictl:")
    assert ctl.main(["veille", "suspendre"]) == 0                  # déjà suspendue : sans changement
    assert ctl.main(["veille", "reprendre"]) == 0
    assert decisions.suspension(db)["suspendu"] is False
    assert ctl.main(["veille", "autre"]) == 2 and ctl.main(["veille"]) == 2
    lignes = [json.loads(x) for x in env.audit.read_text().splitlines()]
    assert [x["evenement"] for x in lignes if x["evenement"].startswith("veille-")] == \
        ["veille-suspendue", "veille-suspendue", "veille-reprise"]
    # écrites par aictl lui-même : jamais relayées une seconde fois par la veille
    assert not db.execute("SELECT 1 FROM audit_chaine WHERE json_extract(details_json, '$.relais') = 1").fetchone()
    db.close()


def test_aictl_acl_audit_refuse_un_lien(ctl, env, monkeypatch, tmp_path):  # noqa: F811
    trace = tmp_path / "setfacl.trace"
    faux = tmp_path / "setfacl"
    faux.write_text(f'#!/bin/sh\necho "$@" >> {trace}\n')
    faux.chmod(0o755)
    monkeypatch.setattr(ctl, "SETFACL", str(faux))
    env.audit.write_text("")
    assert ctl.main(["acl-audit"]) == 0
    assert trace.read_text().split() == ["--physical", "-m", "u:secubox-ai:w", "--", str(env.audit)]
    env.audit.unlink()
    (tmp_path / "ailleurs").write_text("")
    env.audit.symlink_to(tmp_path / "ailleurs")
    assert ctl.cmd_acl_audit() == 2 and len(trace.read_text().splitlines()) == 1


def test_demande_acl_audit_deposee_par_la_veille(ctl, env, monkeypatch):  # noqa: F811
    appels = []
    monkeypatch.setattr(ctl, "cmd_acl_audit", lambda: appels.append("acl") or 0)
    monkeypatch.setattr(ctl, "executer_action", lambda *a, **k: appels.append("moteur") or 0)
    monkeypatch.setenv("SECUBOX_AI_DEMANDES", str(env.run / "demandes"))
    monkeypatch.setitem(executeur._demande_acl, "derniere", 0.0)
    monkeypatch.setenv("SECUBOX_AI_AUDIT", str(env.tmp / "absent" / "audit.log"))
    refuse = env.tmp / "refuse.log"
    refuse.write_text("")
    refuse.chmod(0o400)
    monkeypatch.setenv("SECUBOX_AI_AUDIT", str(refuse))
    if os.geteuid() == 0:
        pytest.skip("root écrit toujours")
    assert executeur.ecrire_audit("essai", {"x": 1}) is False
    assert (env.run / "demandes" / "acl-audit.demande").exists()
    assert ctl.traiter_demandes() == 0 and appels == ["acl"]


# ── correctifs de revue (ronde 1) ──

def _pol(**modifs):
    brut = tomllib.loads((PAQUET / "conf" / "politiques.toml.example").read_text("utf-8"))
    for cle, valeur in modifs.items():
        brut[cle] = {**brut.get(cle, {}), **valeur}
    return politiques.valider(brut)


def test_observation_bloque_tout_meme_approuve(banc):
    pol = _pol(defauts={"mode": "observation"})
    clic = _prop(banc.db, mode="clic", etat="approuvee")
    auto = _prop(banc.db, cible=B, mode="auto")
    _tour(banc, pol=pol)
    assert banc.gk2.appels == [] and _etat(banc.db, clic) == "approuvee" and _etat(banc.db, auto) == "proposee"
    assert json.loads(decisions.lire_etat(banc.db, "politique"))["mode"] == "observation"
    _tour(banc)                                         # retour en hybride : le clic part
    assert _etat(banc.db, clic) == "faite"


def test_clic_jamais_affame_par_une_file_d_office_suspendue(banc):
    decisions.suspendre(banc.db, "admin", _maintenant())
    m = _maintenant()
    for i in range(25):                                  # plus que le lot (20), plus récentes et plus graves
        _prop(banc.db, cible=f"45.83.80.{i}", mode="auto", cree=m, dossier=_dossier(banc.db, f"g{i}", "critical", 4))
    clic = _prop(banc.db, cible=A, mode="clic", etat="approuvee", cree=m - timedelta(hours=1))
    _tour(banc)
    assert _etat(banc.db, clic) == "faite" and [c["cible"] for _, c in banc.gk2.appels] == [A]


@pytest.mark.parametrize("code", [500, 502, 504])
def test_5xx_autre_que_503_issue_inconnue_rapprochee(banc, code):
    m = _maintenant()
    p1 = _prop(banc.db, cible=A, mode="auto", cree=m)
    p2 = _prop(banc.db, cible=B, mode="auto", cree=m - timedelta(seconds=5))
    banc.gk2.forcer = [(code, "incoherent")]
    _tour(banc)
    a = _action(banc.db, p1)
    assert a["etat"] == "envoi" and a["code"] == code and _etat(banc.db, p1) == "envoyee"
    assert _action(banc.db, p2) is None                 # la passe s'arrête
    assert decisions.suspension(banc.db)["suspendu"] is False
    _tour(banc, maintenant=_maintenant() + timedelta(seconds=100))
    assert _action(banc.db, p1)["etat"] == "echec"      # rien chez gk2 : absent, jamais renvoyé
    assert [c["cible"] for _, c in banc.gk2.appels] == [A, B]


def test_503_arrete_la_passe(banc):
    m = _maintenant()
    p1 = _prop(banc.db, cible=A, mode="clic", etat="approuvee", cree=m)
    p2 = _prop(banc.db, cible=B, mode="clic", etat="approuvee", cree=m - timedelta(seconds=5))
    banc.gk2.forcer = [(503, "wafctl")]
    _tour(banc)
    assert _action(banc.db, p1)["etat"] == "echec" and _action(banc.db, p2) is None
    _tour(banc)
    assert _etat(banc.db, p2) == "faite"                # approuvée : partie malgré la suspension


@pytest.mark.parametrize("code", [401, 403])
def test_cle_refusee_suspend_arrete_et_se_voit(banc, code, api):
    m = _maintenant()
    p1 = _prop(banc.db, cible=A, mode="auto", cree=m)
    p2 = _prop(banc.db, cible=B, mode="auto", cree=m - timedelta(seconds=5))
    banc.gk2.forcer = [(code, "x")]
    _tour(banc)
    assert _action(banc.db, p1)["etat"] == "echec" and _action(banc.db, p2) is None
    s = decisions.suspension(banc.db)
    assert s["suspendu"] is True and s["motif"] == "cle_refusee"
    assert json.loads(decisions.lire_etat(banc.db, "cle_refusee"))["code"] == code
    # vu par la console (le même fichier veille.db que l'API)
    c, _ = api
    e = c.get("/veille/etat").json()
    assert e["cle_ai_ban"]["refusee"]["code"] == code and e["suspension"]["motif"] == "cle_refusee"


def test_veille_etat_dit_cle_refusee_et_compte_l_office_suspendu(api):
    c, db = api
    decisions.poser_etat(db, "cle_refusee", json.dumps({"code": 401, "motif": "refus", "le": "x"}), _maintenant())
    decisions.poser_etat(db, "cle_ai_ban", json.dumps({"etat": "presente", "empreinte": "e"}), _maintenant())
    for i in range(3):
        _prop(db, cible=f"45.83.81.{i}", mode="auto")
    _prop(db, cible=A, mode="clic")
    e = c.get("/veille/etat").json()
    assert e["cle_ai_ban"]["refusee"]["code"] == 401
    assert e["a_decider"] == 1 and e["auto_en_attente"] == 3
    decisions.suspendre(db, "admin", _maintenant())
    assert c.get("/veille/etat").json()["a_decider"] == 4


def test_unban_d_un_ban_echu_rapproche_en_echec(banc):
    ban = _prop(banc.db, mode="auto")
    _tour(banc)
    id_gk2 = _action(banc.db, ban)["id_gk2"]
    lev = _prop(banc.db, geste="unban", cible=A, duree=None, reference=ban)
    banc.transport.couper = "apres"
    _tour(banc)
    assert _action(banc.db, lev)["etat"] == "envoi"
    banc.transport.couper = None
    # le ban a échu de lui-même : l'unban n'a rien levé, il ne doit pas sortir le ban de la récidive
    banc.db.execute("UPDATE actions SET fin_gk2 = ? WHERE proposition_id = ?", (int(time.time()) - 10, ban))
    banc.gk2.journal[id_gk2]["fin"] = int(time.time()) - 10
    _tour(banc, maintenant=_maintenant() + timedelta(seconds=100))
    a = _action(banc.db, lev)
    assert a["etat"] == "echec" and a["motif"] == "echue" and _etat(banc.db, lev) == "echec"


def test_unban_rapproche_faite_si_le_ban_court_encore(banc):
    ban = _prop(banc.db, mode="auto")
    _tour(banc)
    lev = _prop(banc.db, geste="unban", cible=A, duree=None, reference=ban)
    banc.transport.couper = "apres"
    _tour(banc)
    banc.transport.couper = None
    _tour(banc, maintenant=_maintenant() + timedelta(seconds=100))
    assert _action(banc.db, lev)["etat"] == "faite" and _etat(banc.db, lev) == "faite"


@pytest.mark.parametrize("geste,cible,duree,motif", [
    ("ban", "10.0.0.1", 86400, "protegee"),
    ("ban", "203.0.113.0/24", 86400, "cible"),          # un /24 n'est pas un ban d'adresse
    ("ban_bloc", "45.83.64.1", 86400, "cible"),
    ("ban_bloc", "45.83.64.0/24", 3 * 86400, "duree"),   # bloc d'office : 24 h au plus
    ("ban", "45.83.064.1", 86400, "cible"),
    ("ban", "45.83.64.1/32", 86400, "cible"),
    ("limiter", "45.83.64.1", 3 * 86400, "duree"),
    ("ban", A, 10, "duree"),
    ("leurre", "::ffff:2d53:4001", 86400, "protegee"),     # IPv4 mêlée (forme canonique)
    ("leurre", "::ffff:45.83.64.1", 86400, "cible"),       # forme non canonique
    ("ban", "198.51.100.7", 86400, "protegee"),          # plage protégée de ai.toml
])
def test_ligne_forgee_jamais_signee(banc, geste, cible, duree, motif):
    import ipaddress as ipa
    pid = _prop(banc.db, geste=geste, cible=cible, duree=duree, mode="auto")
    v = Veille(banc.db, _maintenant, [])
    asyncio.run(executeur.executer(v, banc.client, _maintenant(), politiques=POLITIQUES, journal=banc.journal,
                                   protegees=[ipa.ip_network("198.51.100.0/24")]))
    assert banc.gk2.appels == [] and _etat(banc.db, pid) == "echec" and _action(banc.db, pid) is None
    assert [d["motif"] for ev, d in banc.lignes if ev == "ai-reponse-echec"] == [motif]
    assert not [r for r in banc.transport.requetes if r[0] == "POST"]


def test_approuvee_expiree_auditee(banc):
    pid = _prop(banc.db, mode="clic", etat="approuvee", expire_s=-5)
    _tour(banc)
    assert _etat(banc.db, pid) == "expiree"
    assert [d["proposition"] for ev, d in banc.lignes if ev == "ai-reponse-expiree"] == [pid]


def test_plafond_unban_gk3(banc):
    pol = _pol(plafonds={"unban": {"heure": 1, "jour": 100}})
    assert POLITIQUES.plafonds["unban"] == {"heure": 30, "jour": 100}
    with pytest.raises(politiques.PolitiqueInvalide):
        _pol(plafonds={"unban": {"heure": 31, "jour": 100}})
    bans = []
    for c in (A, B):
        bans.append(_prop(banc.db, cible=c, mode="auto"))
    _tour(banc)
    levees = [_prop(banc.db, geste="unban", cible=c, duree=None, reference=b) for c, b in zip((A, B), bans)]
    _tour(banc, pol=pol)
    assert sorted(_etat(banc.db, x) for x in levees) == ["faite", "proposee"]


def test_unites_api_sans_cle_ni_audit_veille_sortie_fermee():
    api = (PAQUET / "systemd" / "secubox-ai.service").read_text(encoding="utf-8")
    acode = "\n".join(x for x in api.splitlines() if not x.lstrip().startswith("#"))
    # le PARENT, sans « - » (toujours présent) : jamais le seul dossier de la veille, absent ou remonté neuf
    assert re.findall(r"^InaccessiblePaths=.*$", acode, re.M) == ["InaccessiblePaths=/run/credentials"]
    assert "LoadCredential" not in acode and "SetCredential" not in acode and "ImportCredential" not in acode
    assert "/var/log/secubox" not in acode
    veille = (PAQUET / "systemd" / "secubox-ai-veille.service").read_text(encoding="utf-8")
    vcode = "\n".join(x for x in veille.splitlines() if not x.lstrip().startswith("#"))
    assert re.search(r"^IPAddressDeny=any$", vcode, re.M)
    assert re.findall(r"^IPAddressAllow=.*$", vcode, re.M) == ["IPAddressAllow=127.0.0.1/32"]


def test_aictl_drop_in_veille_publiques_comprises(ctl, env, monkeypatch):  # noqa: F811
    resolv = env.tmp / "resolv.conf"
    resolv.write_text("nameserver 192.168.1.200\nnameserver 9.9.9.9\n")
    monkeypatch.setattr(ctl, "RESOLV", resolv)
    env.conf.write_text('[gk2]\nmenaces_url = "https://admin.gk2.example/api/v1"\nsources_url = ""\n'
                        '[distant]\nurl = "https://45.83.90.1:8443"\n[searxng]\nurl = "http://10.100.0.85:8888"\n')
    env.conf.chmod(0o644)
    monkeypatch.setattr(ctl, "resoudre", lambda h: {"45.83.91.2", "127.0.0.1"})
    assert ctl.cmd_preparer() == 0
    veille = (ctl.DROPIN_VEILLE / "50-adresses.conf").read_text()
    api = (ctl.DROPIN_API / "50-adresses.conf").read_text()
    assert [x for x in veille.splitlines() if x.startswith("IPAddressAllow")] == \
        ["IPAddressAllow=192.168.1.200/32 45.83.90.1/32 45.83.91.2/32 9.9.9.9/32"]
    assert "IPAddressDeny=any" in veille or "IPAddressDeny" not in veille     # le drop-in n'en change pas
    assert "45.83.90.1" not in api and "9.9.9.9" not in api                    # l'API : LAN seulement, inchangé
    assert "10.100.0.85" not in veille


def test_aictl_acl_audit_chaque_issue_auditee(ctl, env, monkeypatch, tmp_path):  # noqa: F811
    faux = tmp_path / "setfacl"
    faux.write_text("#!/bin/sh\nexit 1\n")
    faux.chmod(0o755)
    monkeypatch.setattr(ctl, "SETFACL", str(faux))
    env.audit.write_text("")
    assert ctl.cmd_acl_audit() == 1
    faux.write_text("#!/bin/sh\nexit 0\n")
    assert ctl.cmd_acl_audit() == 0
    issues = [json.loads(x)["issue"] for x in env.audit.read_text().splitlines()
              if json.loads(x)["evenement"] == "acl-audit"]
    assert issues == ["erreur", "posee"]


def test_riposte_ne_cree_jamais_audit_log(tmp_path):
    from veille import riposte
    chemin = tmp_path / "audit.log"
    riposte.ecrire_audit_log("essai", {}, chemin=str(chemin))
    assert not chemin.exists()
