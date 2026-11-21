# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Apprentissage (#3723, carte 4) : filtres WAF d'office et suggestions d'empreintes.

Le gk2 simulé sert `/ai/filtres` derrière la VRAIE garde `require_ai_filtres` et passe chaque filtre au VRAI contrôle
de forme et au VRAI vérificateur de gk2 (`wafgen.filtres_ia.lire_filtre` / `verifier`, #3732), plafonds 10/h 50/j.
Aucun réseau.
"""
import asyncio
import json
import os
import re
import stat
import sys
import time
import tomllib
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

import httpx
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi import Depends, FastAPI, HTTPException, Request

from secubox_core import auth
from secubox_core import compte_service as cs
from veille import apprentissage, base, decisions, outils, politiques
from veille.client import ClientGk2
from veille.regles import iso
from veille.service import Veille

PAQUET = Path(__file__).resolve().parents[1]
RACINE = PAQUET.parents[1]
sys.path.insert(0, str(RACINE / "packages" / "secubox-security-posture" / "composants" / "cve-triage" / "api"))
from wafgen import filtres_ia as gk2_filtres  # noqa: E402

POLITIQUES = politiques.valider(tomllib.loads((PAQUET / "conf" / "politiques.toml.example").read_text("utf-8")))


def _paire():
    cle = Ed25519PrivateKey.generate()
    return (cle.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                              serialization.NoEncryption()),
            cle.public_key().public_bytes(serialization.Encoding.PEM,
                                          serialization.PublicFormat.SubjectPublicKeyInfo))


def _poser(tmp_path, compte, publique):
    d = tmp_path / "comptes" / compte
    d.mkdir(parents=True, exist_ok=True)
    os.chmod(tmp_path / "comptes", 0o755)
    os.chmod(d, 0o755)
    f = d / f"{cs.empreinte(publique)}.pub"
    f.write_bytes(publique)
    os.chmod(f, 0o644)


class Gk2:
    """`/ai/filtres` : vraie garde, vrais contrôles de gk2, plafonds 10/h et 50/j, filtres en mémoire."""

    def __init__(self):
        self.filtres = {}
        self.historique = []
        self.appels = []
        self.forcer = []
        self.utilisateurs = []
        self.app = FastAPI()

        @self.app.post("/ai/filtres")
        async def appliquer(request: Request, user=Depends(cs.require_ai_filtres)):
            corps = json.loads(await request.body())
            self.appels.append(("POST", corps))
            self.utilisateurs.append(user)
            if self.forcer:
                statut, motif = self.forcer.pop(0)
                raise HTTPException(statut, detail={"motif": motif})
            bilan = {"appliques": [], "inchanges": [], "rejets": []}
            m = time.time()
            for brut in corps["filtres"]:
                try:
                    f = gk2_filtres.lire_filtre(brut)
                except gk2_filtres.Refus:
                    bilan["rejets"].append({"id": brut.get("id", "?"), "motif": "forme"})
                    continue
                if f.id in self.filtres:
                    bilan["inchanges"].append(f.id)
                    continue
                raison = gk2_filtres.verifier(f, present=set(), vhosts=set(), frequents={"/", "/index.php"},
                                              existants={}, propres=set(gk2_filtres.CHEMINS_SECUBOX_FIXES))
                recents = [t for t in self.historique if m - t < 86400]
                if raison is None and (sum(1 for t in recents if m - t < 3600) >= 10 or len(recents) >= 50):
                    raison = "plafond"
                if raison:
                    bilan["rejets"].append({"id": f.id, "motif": raison})
                    continue
                self.filtres[f.id] = brut
                self.historique.append(m)
                bilan["appliques"].append(f.id)
            if not bilan["appliques"] and not bilan["inchanges"]:
                raise HTTPException(409, detail={"motif": "rejete", "rejets": bilan["rejets"]})
            return bilan

        @self.app.delete("/ai/filtres/{fid}")
        async def retirer(fid: str, request: Request, user=Depends(cs.require_ai_filtres)):
            assert await request.body() == b""
            self.appels.append(("DELETE", fid))
            if fid not in self.filtres:
                raise HTTPException(404, detail={"motif": "refus"})
            del self.filtres[fid]
            return {"id": fid}

        @self.app.get("/ai/filtres")
        async def lister(user=Depends(cs.require_ai_filtres)):
            self.appels.append(("GET", None))
            return {"filtres": [{"id": i} for i in sorted(self.filtres)]}


class Transport(httpx.AsyncBaseTransport):
    def __init__(self, app):
        self.asgi = httpx.ASGITransport(app=app)
        self.couper = None

    async def handle_async_request(self, request):
        r = await self.asgi.handle_async_request(request)
        if self.couper == "apres" and request.method == "POST":
            await r.aread()
            raise httpx.ReadTimeout("coupé")
        return r


def _outil(nom="sqlmap", filtres=None):
    return outils.entree({
        "nom": nom, "source": "doc publique (test)",
        "trait": [{"type": "agent", "couche": "waf", "motif": f"{nom}/"},
                  {"type": "identifiants", "couche": "leurre", "valeurs": ["admin:5", "root:4"], "min": 2}],
        "filtre": filtres if filtres is not None else [
            {"cve": "CVE-2021-41773", "produit": "Apache HTTP Server 2.4.49", "famille": "traversal",
             "motif_type": "chemin_prefixe", "motif": "/cgi-bin/.%2e/.%2e".replace("%2e", "."),
             "source": "https://nvd.nist.gov/vuln/detail/CVE-2021-41773"}]})


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
    filtres_prive, filtres_pub = _paire()
    lec_prive, _ = _paire()
    ban_prive, ban_pub = _paire()
    _poser(tmp_path, "ai-filtres", filtres_pub)
    _poser(tmp_path, "ai-ban", ban_pub)
    gk2 = Gk2()

    class B:
        pass
    b = B()
    b.gk2, b.tmp = gk2, tmp_path
    b.transport = Transport(gk2.app)
    b.db = base.ouvrir(tmp_path / "veille.db")
    b.filtres_pub = filtres_pub
    table = {"ai_filtres": ("/ai/filtres", "/ai/filtres")}
    b.client = ClientGk2("http://gk2", "gk2", lec_prive, table, transport=b.transport, cle_filtres=filtres_prive,
                         cle_ban=ban_prive)
    b.client_ban_seul = ClientGk2("http://gk2", "gk2", lec_prive, table, transport=b.transport,
                                  cle_filtres=ban_prive)
    b.lignes = []
    b.journal = lambda ev, det: b.lignes.append((ev, det)) or True
    b.suggestions = tmp_path / "suggestions-empreintes.json"
    b.cat = [_outil()]
    yield b
    b.db.close()


def _maintenant():
    return datetime.now(timezone.utc)


def _dossier(db, cle, attributions):
    did = str(uuid.uuid4())
    db.execute("INSERT INTO dossiers(id, cle, type, gravite, outils_json, premiere_vue, derniere_vue, maj_le) "
               "VALUES (?, ?, 'acteur', 'high', ?, 'a', ?, 'c')", (did, cle, json.dumps(attributions),
                                                                   iso(_maintenant())))
    return did


def _attribution(nom="sqlmap", traits=2):
    return {"outil": nom, "confiance": "forte",
            "traits_concordants": [{"type": "agent"}, {"type": "identifiants"}][:traits], "traits_observes": []}


def _evt(db, ip, famille="scanners", message=None, attributs=None, quand=None):
    eid = str(uuid.uuid4())
    db.execute("INSERT INTO evenements(id, source, noeud, horodatage, famille, gravite, ip_src, message, "
               "attributs_json, empreinte, cree_le) VALUES (?, 'menaces', 'gk2', ?, ?, 'high', ?, ?, ?, ?, 'x')",
               (eid, iso(quand or _maintenant()), famille, ip, message, json.dumps(attributs or {}), eid))
    return eid


def _tour(b, pol=POLITIQUES, client="defaut", maintenant=None, protegees=()):
    v = Veille(b.db, _maintenant, [])
    asyncio.run(apprentissage.apprendre(v, b.client if client == "defaut" else client, maintenant or _maintenant(),
                                        politiques=pol, journal=b.journal, protegees=protegees, cat=b.cat,
                                        chemin=b.suggestions))


def _etat(db, fid):
    r = db.execute("SELECT etat FROM filtres WHERE id = ?", (fid,)).fetchone()
    return r[0] if r else None


FID = apprentissage.identifiant("sqlmap", "CVE-2021-41773")


# ── tests du brief ──

def test_un_trait_aucun_filtre(banc):
    _dossier(banc.db, "45.83.64.1", [_attribution(traits=1)])
    _dossier(banc.db, "45.83.64.2", [{"outil": "inconnu", "traits_observes": [{"type": "agent"}]}])
    _tour(banc)
    assert [a for a in banc.gk2.appels if a[0] == "POST"] == []
    assert banc.db.execute("SELECT COUNT(*) FROM filtres").fetchone()[0] == 0


def test_deux_traits_filtre_envoye(banc):
    did = _dossier(banc.db, "45.83.64.1", [_attribution()])
    _tour(banc)
    posts = [c for m, c in banc.gk2.appels if m == "POST"]
    assert len(posts) == 1 and [f["id"] for f in posts[0]["filtres"]] == [FID]
    f = posts[0]["filtres"][0]
    gk2_filtres.lire_filtre(f)                                     # le vrai contrôle de forme de gk2
    assert f["cve"] == "CVE-2021-41773" and f["sources"][0]["outil"] == "sqlmap"
    assert banc.gk2.utilisateurs[0]["sub"] == "ai-filtres"
    assert banc.gk2.utilisateurs[0]["cle"] == cs.empreinte(banc.filtres_pub)
    r = banc.db.execute("SELECT etat, dossier_id, jti, cle FROM filtres WHERE id = ?", (FID,)).fetchone()
    assert r[0] == "essai" and r[1] == did and r[2] == banc.gk2.utilisateurs[0]["jti"]
    evs = [ev for ev, _ in banc.lignes]
    assert "ai-filtre-envoi" in evs and "ai-filtre-reponse" in evs
    _tour(banc)                                                    # jamais renvoyé
    assert len([1 for m, _ in banc.gk2.appels if m == "POST"]) == 1


def test_confirmation_apres_24h_sans_touche_protegee(banc, tmp_path, monkeypatch):
    """Sans touche protégée après 24 h : `a_confirmer`, JAMAIS confirmé d'office (le critère « réponse légitime »
    n'est pas mesurable depuis gk3) ; un clic d'administrateur le confirme."""
    _dossier(banc.db, "45.83.64.1", [_attribution()])
    _tour(banc)
    _evt(banc.db, "45.83.70.9", famille="ia_filtres_haute", message=FID)          # touche publique : sans effet
    _tour(banc, maintenant=_maintenant() + timedelta(hours=23))
    assert _etat(banc.db, FID) == "essai"
    _tour(banc, maintenant=_maintenant() + timedelta(hours=25))
    assert _etat(banc.db, FID) == "a_confirmer"
    _tour(banc, maintenant=_maintenant() + timedelta(hours=49))
    assert _etat(banc.db, FID) == "a_confirmer"                  # jamais d'office
    assert any(ev == "ai-filtre-a-confirmer" and d["critere_legitime"] == "non_mesurable_depuis_gk3"
               for ev, d in banc.lignes)
    # un clic : par l'API (require_jwt), audité et relayé
    from fastapi.testclient import TestClient
    from secubox_core.auth import require_jwt
    from api.main import app
    monkeypatch.setenv("SECUBOX_AI_ETAT", str(tmp_path))
    app.dependency_overrides[require_jwt] = lambda: {"sub": "admin"}
    try:
        c = TestClient(app)
        assert c.post("/filtres/ia-inconnu/confirmer").status_code == 404
        r = c.post(f"/filtres/{FID}/confirmer")
        assert r.status_code == 200 and r.json()["etat"] == "confirme"
        assert c.post(f"/filtres/{FID}/confirmer").status_code == 409
        vue = c.get("/filtres").json()
        assert vue["etat"]["filtres_confirmes"] == 1 and vue["critere_legitime"] == "non_mesurable_depuis_gk3"
    finally:
        app.dependency_overrides.pop(require_jwt, None)
    assert banc.db.execute("SELECT confirme_par FROM filtres WHERE id = ?", (FID,)).fetchone()[0] == "admin"


def test_retrait_si_reponse_legitime_touchee(banc):
    """Le critère mesurable depuis gk3 : une touche d'adresse PROTÉGÉE (non publique, `local`, plage protégée) fait
    retirer le filtre d'office, avec alerte ; même confirmé, même suspendu. (« Vhost routé à réponse 2xx/3xx » n'est
    pas mesurable depuis gk3 : README § Suite.)"""
    _dossier(banc.db, "45.83.64.1", [_attribution()])
    _tour(banc)
    assert FID in banc.gk2.filtres
    _evt(banc.db, None, famille="ia_filtres_haute", message=FID, attributs={"local": True})
    decisions.suspendre(banc.db, "admin", _maintenant())
    _tour(banc)
    assert _etat(banc.db, FID) == "retire" and FID not in banc.gk2.filtres
    assert ("DELETE", FID) in banc.gk2.appels
    evs = [ev for ev, _ in banc.lignes]
    assert "ai-filtre-retire" in evs and "ai-filtre-alerte" in evs
    assert banc.db.execute("SELECT touches_protegees, motif FROM filtres WHERE id = ?", (FID,)).fetchone() == \
        (1, "touche_protegee")
    assert banc.db.execute("SELECT COUNT(*) FROM audit_chaine WHERE operation = 'filtre_retire'").fetchone()[0] == 1
    decisions.reprendre(banc.db, "admin", _maintenant())
    _tour(banc)                                                    # un id retiré n'est jamais renvoyé
    assert len([1 for m, _ in banc.gk2.appels if m == "POST"]) == 1


@pytest.mark.parametrize("ip", ["192.168.1.20", "198.51.100.9"])
def test_retrait_sur_adresse_privee_ou_plage_protegee(banc, ip):
    import ipaddress
    _dossier(banc.db, "45.83.64.1", [_attribution()])
    _tour(banc)
    decisions.poser_etat(banc.db, "x", "y", _maintenant())
    banc.db.execute("UPDATE filtres SET etat = 'confirme' WHERE id = ?", (FID,))
    _evt(banc.db, ip, famille="ia_filtres_critique", message=FID)
    _tour(banc, protegees=[ipaddress.ip_network("198.51.100.0/24")])
    assert _etat(banc.db, FID) == "retire"


def test_suggestion_jamais_appliquee(banc):
    for i in range(30):
        _evt(banc.db, f"45.83.90.{i}", attributs={"user_agent": "Etrange-Scanner/0.9", "tool": "inconnu-x"})
    for i in range(29):
        _evt(banc.db, f"45.83.91.{i}", attributs={"user_agent": "Rare/1"})
    # une adresse d'un dossier à outil NOMMÉ ne compte pas
    _tour(banc, client=None)
    d = json.loads(banc.suggestions.read_text())
    assert d["jamais_appliquees"] is True and d["seuil_adresses"] == 30
    vals = {(s["type"], s["valeur"]): s["adresses"] for s in d["suggestions"]}
    assert vals == {("agent", "Etrange-Scanner/0.9"): 30, ("outil_waf", "inconnu-x"): 30}
    assert stat.S_IMODE(banc.suggestions.stat().st_mode) == 0o640
    _tour(banc)
    assert banc.gk2.appels == [] and banc.db.execute("SELECT COUNT(*) FROM filtres").fetchone()[0] == 0
    assert apprentissage.etat_apprentissage(banc.db, banc.suggestions)["suggestions"] == 2
    # aucun code n'agit sur les suggestions
    for f in (PAQUET / "veille").glob("*.py"):
        texte = f.read_text(encoding="utf-8")
        assert "suggestions-empreintes" not in texte or f.name == "apprentissage.py", f.name


def test_suggestions_hors_adresses_attribuees_et_bornees(banc):
    did = _dossier(banc.db, "acteur", [_attribution()])
    for i in range(30):
        eid = _evt(banc.db, f"45.83.92.{i}", attributs={"user_agent": "Attribue/1"})
        banc.db.execute("INSERT INTO dossier_evenements(dossier_id, evenement_id) VALUES (?, ?)", (did, eid))
    s = apprentissage.calculer_suggestions(banc.db, _maintenant(), banc.cat)
    assert s == []


def test_plafond_ai_filtres_respecte(banc):
    cves = [f"CVE-2024-{1000 + i}" for i in range(12)]
    banc.cat = [_outil(filtres=[{"cve": c, "produit": "Produit absent", "famille": "rce",
                                 "motif_type": "chemin_exact", "motif": f"/sonde-unique-{c.lower()}",
                                 "source": "relevé gk2 2026-11-21"} for c in cves])]
    _dossier(banc.db, "45.83.64.1", [_attribution()])
    for _ in range(4):
        _tour(banc)
    assert banc.db.execute("SELECT COUNT(*) FROM filtres").fetchone()[0] == 10       # 10 par heure
    assert len(banc.gk2.filtres) == 10
    _tour(banc, maintenant=_maintenant() + timedelta(hours=2))
    assert banc.db.execute("SELECT COUNT(*) FROM filtres").fetchone()[0] == 12
    # 50 par jour : déjà 50 envois dans la journée → rien
    banc.db.execute("DELETE FROM filtres")
    m = _maintenant()
    for i in range(50):
        banc.db.execute("INSERT INTO filtres(id, outil, cve, corps_json, etat, envoye_le, maj_le) VALUES "
                        "(?, 'x', 'CVE-2020-0001', '{}', 'retire', ?, 'x')",
                        (f"ia-autre-{i}", iso(m - timedelta(hours=3 + i * 0.3))))
    n = len(banc.gk2.appels)
    _tour(banc)
    assert [a for a in banc.gk2.appels[n:] if a[0] == "POST"] == []


# ── compléments ──

def test_observation_ou_suspendu_aucun_envoi(banc):
    _dossier(banc.db, "45.83.64.1", [_attribution()])
    brut = tomllib.loads((PAQUET / "conf" / "politiques.toml.example").read_text("utf-8"))
    brut["defauts"]["mode"] = "observation"
    _tour(banc, pol=politiques.valider(brut))
    decisions.suspendre(banc.db, "admin", _maintenant())
    _tour(banc)
    assert [a for a in banc.gk2.appels if a[0] == "POST"] == []
    decisions.reprendre(banc.db, "admin", _maintenant())
    _tour(banc)
    assert _etat(banc.db, FID) == "essai"


def test_cle_absente_ou_cle_ban_refusee(banc):
    _dossier(banc.db, "45.83.64.1", [_attribution()])
    sans = ClientGk2("http://gk2", "gk2", b"x", {"ai_filtres": ("/ai/filtres", "/ai/filtres")},
                     transport=banc.transport)
    _tour(banc, client=sans)
    assert banc.gk2.appels == []
    assert json.loads(decisions.lire_etat(banc.db, "cle_ai_filtres"))["etat"] == "absente"
    # une clé ai-ban n'ouvre pas la route des filtres (portée waf-filtres) : 401, échec, fin de passe
    _tour(banc, client=banc.client_ban_seul)
    r = banc.db.execute("SELECT etat, code_http FROM filtres WHERE id = ?", (FID,)).fetchone()
    assert r == ("echec", 401) and banc.gk2.filtres == {}


def test_rejet_du_verificateur_jamais_renvoye(banc):
    banc.cat = [_outil(filtres=[{"cve": "CVE-2024-0001", "produit": "Produit absent", "famille": "autre",
                                 "motif_type": "chemin_exact", "motif": "/a.php", "source": "doc"}])]
    _dossier(banc.db, "45.83.64.1", [_attribution()])
    _tour(banc)
    fid = apprentissage.identifiant("sqlmap", "CVE-2024-0001")
    assert banc.db.execute("SELECT etat, motif FROM filtres WHERE id = ?", (fid,)).fetchone() == \
        ("rejete", "specificite")
    _tour(banc)
    assert len([1 for m, _ in banc.gk2.appels if m == "POST"]) == 1


def test_envoi_perdu_rapproche_jamais_renvoye(banc):
    _dossier(banc.db, "45.83.64.1", [_attribution()])
    banc.transport.couper = "apres"
    _tour(banc)
    assert _etat(banc.db, FID) == "envoi"
    banc.transport.couper = None
    _tour(banc, maintenant=_maintenant() + timedelta(seconds=30))
    assert _etat(banc.db, FID) == "envoi"                         # trop tôt : on attend
    _tour(banc, maintenant=_maintenant() + timedelta(seconds=200))
    assert _etat(banc.db, FID) == "essai"
    assert len([1 for m, _ in banc.gk2.appels if m == "POST"]) == 1


def test_etat_apprentissage_none_si_inconnu(tmp_path):
    assert apprentissage.etat_apprentissage(None, tmp_path / "absent.json") == {
        "filtres_essai": None, "filtres_a_confirmer": None, "filtres_confirmes": None, "filtres_retires": None,
        "suggestions": None}
    import sqlite3
    db = sqlite3.connect(":memory:")
    assert apprentissage.etat_apprentissage(db, tmp_path / "absent.json")["filtres_essai"] is None
    db = base.ouvrir(tmp_path / "v.db")
    assert apprentissage.etat_apprentissage(db, tmp_path / "absent.json")["filtres_essai"] == 0
    db.close()


def test_catalogue_filtre_source_et_forme():
    with pytest.raises(ValueError):
        _outil(filtres=[{"cve": "CVE-2021-41773", "produit": "p", "famille": "rce", "motif_type": "chemin_exact",
                         "motif": "/x/y/z/abc"}])                       # sans source
    with pytest.raises(ValueError):
        _outil(filtres=[{"cve": "pas-un-cve", "produit": "p", "famille": "rce", "motif_type": "chemin_exact",
                         "motif": "/x", "source": "s"}])
    assert all(not o.filtres for o in outils.charger([PAQUET / "empreintes"]))   # rien de livré aujourd'hui
    assert re.fullmatch(r"ia-[a-z0-9._-]{1,93}", apprentissage.identifiant("Nom Bizarre/2", "CVE-2021-41773"))


def test_unite_profil_et_routes():
    unite = (PAQUET / "systemd" / "secubox-ai-veille.service").read_text(encoding="utf-8")
    assert "LoadCredential=ai-filtres:/etc/secubox/secrets/ai/ai-filtres.key" in unite
    assert "SetCredential=ai-filtres:absente" in unite
    profil = (PAQUET / "apparmor" / "secubox-ai-veille").read_text(encoding="utf-8")
    assert "/run/credentials/secubox-ai-veille.service/ai-filtres r," in profil
    from fastapi.routing import APIRoute
    from secubox_core.auth import require_jwt
    from api.main import app
    routes = {(m, r.path): r for r in app.routes if isinstance(r, APIRoute) for m in r.methods}
    for cle in (("GET", "/filtres"), ("GET", "/filtres/suggestions"), ("POST", "/filtres/{fid}/confirmer")):
        assert require_jwt in [d.call for d in routes[cle].dependant.dependencies], cle


from test_aictl_3583 import ctl, env  # noqa: E402,F401


def test_aictl_cle_ai_filtres(ctl, env, monkeypatch, capsys):  # noqa: F811
    cle = env.tmp / "secrets" / "ai" / "ai-filtres.key"
    monkeypatch.setenv("SECUBOX_AI_CLE_FILTRES", str(cle))
    assert ctl.main(["cle-ai-filtres", "generer"]) == 0
    sortie = capsys.readouterr().out
    assert sortie.startswith("-----BEGIN PUBLIC KEY-----") and "PRIVATE" not in sortie
    assert stat.S_IMODE(cle.stat().st_mode) == 0o600
    avant = cle.read_bytes()
    assert ctl.main(["cle-ai-filtres", "generer"]) == 2 and cle.read_bytes() == avant
    lignes = [json.loads(x) for x in env.audit.read_text().splitlines()]
    assert any(x["evenement"] == "cle-ai-filtres" and x.get("empreinte") == cs.empreinte(sortie.encode())
               for x in lignes)
    monkeypatch.setattr(ctl, "_root", lambda: False)
    assert ctl.main(["cle-ai-filtres", "generer"]) == 2


