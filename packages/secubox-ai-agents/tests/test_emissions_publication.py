# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""Task 17 (#4058) : publication sur les billets — balayage final bloquant, captures validées, FAUX serveur billets."""
import asyncio
import json

import httpx
import pytest

from emissions import capture, production, publication
from emissions.magasin import Magasin

DOSSIER = {"sujet": {"genre": "campagne", "id": "c1", "nom": "Essai"}, "chiffres": {"bans_90j": 1204}}
REPS = [{"rang": 0, "voix": 1, "texte": "La campagne Essai compte 1 204 bans.", "statut": "verifiee", "marque": "✓"},
        {"rang": 1, "voix": 2, "texte": "Et après ?", "statut": "ia_seule", "marque": "⚠"},
        {"rang": 2, "voix": 1, "texte": "Elle vient de 192.0.2.7.", "statut": "retiree", "marque": "✗"}]


class FauxBillets:
    def __init__(self):
        self.vues = []

    def __call__(self, req):
        self.vues.append((req.method, req.url.path, req.headers.get("authorization"),
                          req.content if req.method != "POST" or not req.url.path.endswith("/media") else b""))
        if req.method == "POST" and req.url.path == "/admin/api/billets":
            return httpx.Response(200, json={"success": True, "id": "B1", "slug": "s"})
        if req.url.path.endswith("/media"):
            return httpx.Response(200, json={"success": True, "id": "M"})
        if req.method == "PUT":
            return httpx.Response(200, json={"success": True, "id": "B1", "url": "https://billets.exemple/b/s"})
        return httpx.Response(200, json={})


def brouillon(tmp_path, chapeau="Ce qui a changé.", ocr_texte="bans par semaine"):
    e = production.creer(tmp_path, ["campagne/c1"], "sujet", 0.0)
    d = production.dossier(tmp_path, e["id"])
    (d / "diapos").mkdir()
    (d / "diapos" / "00-bans.png").write_bytes(b"\x89PNG\r\n\x1a\n")
    (d / "emission.mp3").write_bytes(b"ID3")
    (d / "faits.json").write_text(json.dumps({"campagne/c1": DOSSIER}))
    e.update(statut="pret", titre="Décryptage — Essai", chapeau=chapeau, repliques=REPS, images=["diapos/00-bans.png"],
             chronologie=[{"debut_s": 0.0, "fin_s": 2.0, "diapo": 0, "replique": REPS[0]["texte"]},
                          {"debut_s": 2.45, "fin_s": 3.0, "diapo": 0, "replique": "Et après ?"}])
    e["etapes"] = [{"nom": n, "etat": "faite"} for n in production.ETAPES]
    production.ecrire_etat(tmp_path, e)
    return d, (lambda p: ocr_texte)


def publier(d, ocr, faux, magasin=None):
    async def go():
        async with httpx.AsyncClient(transport=httpx.MockTransport(faux), base_url="https://billets.exemple") as c:
            return await publication.publier(d, "https://billets.exemple", lambda: "jeton-billets", client=c, ocr=ocr,
                                             noms_internes=["gk2"], magasin=magasin)
    return asyncio.run(go())


def test_publier_envoie_dans_l_ordre(tmp_path):
    d, ocr = brouillon(tmp_path)
    faux = FauxBillets()
    m = Magasin(tmp_path / "m.sqlite")
    r = publier(d, ocr, faux, m)
    assert r["billet"] == "B1"
    chemins = [(v[0], v[1]) for v in faux.vues]
    assert chemins == [("POST", "/admin/api/billets"), ("POST", "/admin/api/billets/B1/media"),
                       ("POST", "/admin/api/billets/B1/media"), ("PUT", "/admin/api/billets/B1")]
    assert all(v[2] == "Bearer jeton-billets" for v in faux.vues)
    cree, fin = json.loads(faux.vues[0][3]), json.loads(faux.vues[-1][3])
    assert cree["status"] == "draft" and fin["status"] == "published" and len(fin["chronologie"]) == 2
    assert "192.0.2.7" not in json.dumps(fin)                                 # la retirée n'est pas publiée
    assert json.loads((d / "etat.json").read_text())["statut"] == "publie"


def test_publier_alimente_magasin(tmp_path):
    d, ocr = brouillon(tmp_path)
    m = Magasin(tmp_path / "m.sqlite")
    publier(d, ocr, FauxBillets(), m)
    assert m.dernier_valide("campagne/c1") == DOSSIER
    assert [(i["phrase"], i["statut"]) for i in m.interpretations("campagne/c1")] == [
        (REPS[0]["texte"], "verifiee"), ("Et après ?", "hypothese")]


def test_publier_refuse_si_balayage(tmp_path):
    for kw in ({"chapeau": "Vu depuis gk2."}, {"ocr_texte": "source 198.51.100.4"}):
        d, ocr = brouillon(tmp_path / str(len(kw.get("chapeau", ""))), **kw)
        faux = FauxBillets()
        with pytest.raises(publication.Refus) as e:
            publier(d, ocr, faux)
        assert faux.vues == []                                                 # aucune requête vers les billets
        assert e.value.motifs and all("198.51" not in str(m) for m in e.value.motifs)


def test_capture_non_validee_bloque(tmp_path):
    d, ocr = brouillon(tmp_path)
    capture.enregistrer_capture(d, "c1", {"png": d / "captures" / "c1.png", "masques": 2, "controle": [],
                                          "etat": "a_valider"})
    faux = FauxBillets()
    with pytest.raises(publication.Refus):
        publier(d, ocr, faux)
    assert faux.vues == []


def test_echec_billets_retire_le_brouillon_distant(tmp_path):
    d, ocr = brouillon(tmp_path)
    faux = FauxBillets()

    def panne(req):
        if req.url.path.endswith("/media"):
            faux.vues.append((req.method, req.url.path, None, b""))
            return httpx.Response(507, json={"detail": "espace"})
        return faux(req)
    with pytest.raises(publication.EchecBillets):
        publier(d, ocr, panne)
    assert faux.vues[-1][:2] == ("DELETE", "/admin/api/billets/B1")
    assert json.loads((d / "etat.json").read_text())["statut"] == "pret"


def test_route_publier(tmp_path):
    """Route du service : contrôle à blanc puis publication vers le FAUX serveur billets ; refus = 409 + motifs."""
    import secrets
    from fastapi.testclient import TestClient
    from emissions import app as appmod
    from test_emissions_service import Outils
    j = tmp_path / "jeton"
    j.write_text(secrets.token_urlsafe(32))
    j.chmod(0o600)
    base = tmp_path / "etat"
    d, ocr = brouillon(base)
    faux = FauxBillets()
    client = httpx.AsyncClient(transport=httpx.MockTransport(faux), base_url="https://billets.exemple")
    application = appmod.creer_app(base=base, outils=Outils(tmp_path), jeton=j, jeton_billets=lambda: "jb",
                                   client_billets=client, publier_ocr=ocr)
    h = {"Authorization": f"Bearer {j.read_text()}"}
    with TestClient(application) as c:
        assert c.get(f"/{d.name}/controle", headers=h).json() == {"motifs": []}
        r = c.post(f"/{d.name}/publier", headers=h)
        assert r.status_code == 200 and r.json()["billet"] == "B1"
        assert c.post(f"/{d.name}/publier", headers=h).status_code == 409           # déjà publié
        d2, _ = brouillon(base, chapeau="Joignable sur gk2.")
        n = len(faux.vues)
        r = c.post(f"/{d2.name}/publier", headers=h)
        assert r.status_code == 409 and r.json()["detail"]["motifs"][0]["motif"] == "nom_interne" and len(faux.vues) == n
