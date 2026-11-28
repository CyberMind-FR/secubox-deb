# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""Task 14 (#4058) : service, file de production (une à la fois, reprise) et routes locales — tout en FAUX outils
(gk2, LLM, voix, montage) : aucun réseau, aucun GPU."""
import asyncio
import json
import secrets
import sys
from pathlib import Path

import pytest
from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient

from conftest import PAQUET
from emissions import production
from emissions.magasin import Magasin

if str(PAQUET / "relais") not in sys.path:
    sys.path.insert(0, str(PAQUET / "relais"))

DOSSIER = {"sujet": {"genre": "campagne", "id": "c1", "nom": "Essai"},
           "chiffres": {"bans_90j": 1204, "adresses_90j": 87}, "tendances": [],
           "serie_semaine": [{"debut": "2026-11-16", "bans": 204}, {"debut": "2026-11-23", "bans": 1000}]}
SORTIE_LLM = ("V1: La campagne Essai compte 1 204 bans.\nV2: Et qu'est-ce que cela change ?\n"
              "V1: La campagne Essai compte 9 999 bans.")


class FauxSources:
    def __init__(self):
        self.appels = []

    async def lister(self):
        return [{"cle": "campagne:c1", "genre": "campagne", "id": "c1", "nom": "Essai", "bans_90j": 1204, "vagues": 1}]

    async def dossier(self, genre, ident):
        self.appels.append((genre, ident))
        return {"dossier": DOSSIER, "ia": {"etat": "fait"}}


class Outils(production.Outils):
    """Outils factices : comptent les appels ; `bloquer` retient l'écriture du dialogue."""

    def __init__(self, tmp, bloquer=None, casser=None):
        self.nb_ecrire = self.nb_dire = self.nb_monter = 0
        self.bloquer, self.casser = bloquer, casser
        super().__init__(sources=FauxSources(), magasin=Magasin(tmp / "m.sqlite"), ecrire=self._ecrire,
                         dire=self._dire, monter=self._monter, png=self._png, maintenant=lambda: 1764300000.0,
                         reglages=lambda: dict(production.reglages.DEFAUTS))

    async def _ecrire(self, consigne):
        self.nb_ecrire += 1
        if self.casser == "dialogue":
            raise RuntimeError("coupure")
        if self.bloquer is not None:
            await self.bloquer.wait()
        return SORTIE_LLM

    async def _dire(self, brouillon, repliques, voix, voix_gpu):
        self.nb_dire += 1
        d = Path(brouillon) / "voix"
        d.mkdir(exist_ok=True)
        out = []
        for r in repliques:
            if r.get("statut") == "retiree":
                continue
            p = d / f"{r['rang']}-x.mp3"
            p.write_bytes(b"ID3")
            out.append(p)
        return out

    def _monter(self, fichiers, repliques, diapos, sortie):
        self.nb_monter += 1
        Path(sortie).write_bytes(b"ID3")
        return Path(sortie), [{"debut_s": 0.0, "fin_s": 1.0, "diapo": 0, "replique": "x"}]

    def _png(self, svg, sortie):
        Path(sortie).write_bytes(b"\x89PNG\r\n\x1a\n")
        return Path(sortie)


def test_production_complete_retiree_jamais_dite(tmp_path):
    o = Outils(tmp_path)
    e = production.creer(tmp_path, ["campagne/c1"], "sujet", o.maintenant())
    asyncio.run(production.produire(tmp_path, e["id"], o))
    etat = production.lire_etat(tmp_path, e["id"])
    assert [x["etat"] for x in etat["etapes"]] == ["faite"] * 7 and etat["statut"] == "pret"
    assert [r["marque"] for r in etat["repliques"]] == ["✓", "✓", "✗"]
    assert sorted(p.name for p in (production.dossier(tmp_path, e["id"]) / "voix").iterdir()) == ["0-x.mp3", "1-x.mp3"]
    assert etat["chronologie"] and (production.dossier(tmp_path, e["id"]) / "emission.mp3").is_file()
    assert not list(production.dossier(tmp_path, e["id"]).glob("*.mp4"))


def test_une_production_a_la_fois(tmp_path):
    verrou = asyncio.Event()
    o = Outils(tmp_path, bloquer=verrou)
    a = production.creer(tmp_path, ["campagne/c1"], "sujet", o.maintenant())
    b = production.creer(tmp_path, ["campagne/c1"], "sujet", o.maintenant())

    async def go():
        f = production.File(tmp_path, o)
        f.demarrer()
        await f.mettre(a["id"])
        await f.mettre(b["id"])
        for _ in range(200):
            await asyncio.sleep(0.01)
            if o.nb_ecrire == 1:
                break
        eb = production.lire_etat(tmp_path, b["id"])
        assert o.nb_ecrire == 1 and eb["statut"] == "en_file"
        assert eb["etape"] == 1 and all(x["etat"] == "a_faire" for x in eb["etapes"])      # étape intacte
        assert f.en_cours == a["id"] and f.attente() == [b["id"]]
        verrou.set()
        await f.vider()
        await f.arreter()
    asyncio.run(go())
    assert production.lire_etat(tmp_path, a["id"])["statut"] == "pret"
    assert production.lire_etat(tmp_path, b["id"])["statut"] == "pret"


def test_synthese_passe_devant(tmp_path):
    o = Outils(tmp_path)
    f = production.File(tmp_path, o)
    s = [production.creer(tmp_path, ["campagne/c1"], fmt, 0.0)["id"] for fmt in ("sujet", "sujet", "synthese")]

    async def go():
        for i in s:
            await f.mettre(i)
    asyncio.run(go())
    assert f.attente() == [s[2], s[0], s[1]]


def test_reprise_apres_coupure(tmp_path):
    o = Outils(tmp_path, casser="dialogue")
    e = production.creer(tmp_path, ["campagne/c1"], "sujet", 0.0)
    with pytest.raises(RuntimeError):
        asyncio.run(production.produire(tmp_path, e["id"], o))
    etat = production.lire_etat(tmp_path, e["id"])
    assert etat["statut"] == "erreur" and etat["etape"] == 4
    assert [x["etat"] for x in etat["etapes"]][:4] == ["faite", "faite", "faite", "erreur"]
    o.casser = None
    asyncio.run(production.produire(tmp_path, e["id"], o))
    assert len(o.sources.appels) == 1                                   # les faits ne sont pas relus
    assert production.lire_etat(tmp_path, e["id"])["statut"] == "pret"


def test_modifier_replique_ne_refait_que_voix_et_montage(tmp_path):
    o = Outils(tmp_path)
    e = production.creer(tmp_path, ["campagne/c1"], "sujet", 0.0)
    asyncio.run(production.produire(tmp_path, e["id"], o))
    r = production.modifier_replique(tmp_path, e["id"], 2, "La campagne Essai compte 87 adresses.")
    assert r["statut"] == "verifiee" and r["marque"] == "✓"
    etat = production.lire_etat(tmp_path, e["id"])
    assert [x["etat"] for x in etat["etapes"]] == ["faite"] * 5 + ["a_faire", "a_faire"]
    asyncio.run(production.produire(tmp_path, e["id"], o))
    assert (o.nb_ecrire, o.nb_dire, o.nb_monter) == (1, 2, 2)


def test_reecrire_propose_sans_appliquer(tmp_path):
    o = Outils(tmp_path)
    e = production.creer(tmp_path, ["campagne/c1"], "sujet", 0.0)
    asyncio.run(production.produire(tmp_path, e["id"], o))

    async def propose(consigne):
        assert "9 999" in consigne and "N'utilise QUE" in consigne
        return "V1: La campagne Essai compte 1 204 bans."
    o.ecrire = propose
    p = asyncio.run(production.reecrire(tmp_path, e["id"], 2, o))
    assert p["texte"] == "La campagne Essai compte 1 204 bans." and p["statut"] == "verifiee"
    assert production.lire_etat(tmp_path, e["id"])["repliques"][2]["statut"] == "retiree"      # rien appliqué


def test_identifiant_refuse(tmp_path):
    for mauvais in ("../x", "e1", "", "e20261128000000-zzzzzz"):
        with pytest.raises(ValueError):
            production.dossier(tmp_path, mauvais)


# ── service HTTP ────────────────────────────────────────────────────────────────────────────────────────────────
@pytest.fixture
def service(tmp_path, monkeypatch):
    j = tmp_path / "jeton"
    j.write_text(secrets.token_urlsafe(32))
    j.chmod(0o600)
    from emissions import app as appmod
    o = Outils(tmp_path)
    application = appmod.creer_app(base=tmp_path / "etat", outils=o, jeton=j)
    with TestClient(application) as c:
        yield c, j.read_text(), o


def test_service_exige_jeton(service):
    c, jeton, _ = service
    assert c.get("/health").status_code == 200
    assert c.get("/brouillons").status_code == 401
    assert c.get("/brouillons", headers={"Authorization": "Bearer faux"}).status_code == 401
    assert c.get("/brouillons", headers={"Authorization": f"Bearer {jeton}"}).status_code == 200


def test_service_produire_et_lire(service):
    c, jeton, _ = service
    h = {"Authorization": f"Bearer {jeton}"}
    assert c.post("/produire", json={"sources": ["campagne/c1"], "format": "autre"}, headers=h).status_code == 422
    assert c.post("/produire", json={"sources": ["../x"], "format": "sujet"}, headers=h).status_code == 422
    r = c.post("/produire", json={"sources": ["campagne/c1"], "format": "sujet"}, headers=h)
    assert r.status_code == 200
    ident = r.json()["id"]
    for _ in range(100):
        e = c.get(f"/{ident}", headers=h).json()
        if e["statut"] == "pret":
            break
        import time
        time.sleep(0.02)
    assert e["statut"] == "pret" and e["verification"] == {"verifiee": 2, "ia_seule": 0, "retiree": 1}
    assert c.get(f"/{ident}/fichier/emission.mp3", headers=h).content == b"ID3"
    assert c.get(f"/{ident}/fichier/consigne.txt", headers=h).status_code == 404       # liste blanche de fichiers
    assert c.get("/sources", headers=h).json()["sujets"][0]["evolutions"] >= 1
    # gk2 dit « campagne:c1 » ; la page renvoie la clé telle quelle à /produire, qui exige « genre/id »
    assert c.get("/sources", headers=h).json()["sujets"][0]["cle"] == "campagne/c1"
    assert c.post("/reglages", json={"gk2_base": "https://ailleurs"}, headers=h).status_code == 422
    assert c.post("/reglages", json={"seuil": 4, "voix_gpu": False}, headers=h).json()["seuil"] == 4
    assert c.delete(f"/{ident}", headers=h).json() == {"supprime": ident}


def test_routes_locales_seulement(tmp_path, monkeypatch):
    import emissions_relais

    def local(request):
        if request.headers.get("host") not in {"127.0.0.1:8098", "localhost:8098"}:
            raise HTTPException(403, "local seulement")

    monkeypatch.setattr(emissions_relais, "SOCKET", tmp_path / "absent.sock")
    app = FastAPI()
    emissions_relais.brancher(app, local)
    c = TestClient(app)
    for chemin in ("/emissions", "/api/v1/ai/emissions/brouillons"):
        assert c.get(chemin, headers={"host": "ai.gk2.secubox.in"}).status_code == 403
    assert c.get("/api/v1/ai/emissions/brouillons", headers={"host": "127.0.0.1:8098"}).status_code == 503
    assert c.get("/api/v1/ai/emissions/../x", headers={"host": "127.0.0.1:8098"}).status_code in (403, 404)
    assert c.post("/api/v1/ai/emissions/produire", content=b"x" * (emissions_relais.CORPS_MAX + 1),
                  headers={"host": "127.0.0.1:8098"}).status_code == 413


def test_etat_json_0600(tmp_path):
    e = production.creer(tmp_path, ["campagne/c1"], "sujet", 0.0)
    f = production.dossier(tmp_path, e["id"]) / "etat.json"
    assert f.stat().st_mode & 0o077 == 0 and json.loads(f.read_text())["etape"] == 1


def test_installateur_idempotent(tmp_path):
    """installer-emissions.sh dans un HOME factice : deux passages → deux lignes et un onglet, pas davantage."""
    import os
    import subprocess
    home, bin_ = tmp_path / "home", tmp_path / "bin"
    rel = home / "poc-secubox-ai/relais"
    rel.mkdir(parents=True)
    bin_.mkdir()
    (rel / "relais.py").write_text("app = None\ndef _local(r):\n    pass\n")
    (rel / "index.html").write_text("var ONGLETS = [['essai', 'Essai'], ['filtres', 'Filtres WAF'], ['code', 'Code']];\n"
                                    '  <section data-o="essai" class="pan"></section>\n')
    for outil, corps in (("systemctl", "exit 0"), ("getent", "echo '192.0.2.10 STREAM x'")):
        (bin_ / outil).write_text(f"#!/bin/sh\n{corps}\n")
        (bin_ / outil).chmod(0o755)
    env = {**os.environ, "HOME": str(home), "PATH": f"{bin_}:{os.environ['PATH']}"}
    for _ in range(2):
        r = subprocess.run(["bash", str(PAQUET / "sbin/installer-emissions.sh"), str(PAQUET), sys.executable],
                           env=env, capture_output=True, text=True)
        assert r.returncode == 0, r.stderr
    relais = (rel / "relais.py").read_text()
    assert relais.count("import emissions_relais") == 1 and relais.count("emissions_relais.brancher(app, _local)") == 1
    idx = (rel / "index.html").read_text()
    assert idx.count("['emissions', 'Émissions']") == 1 and idx.count('data-o="emissions"') == 1
    assert idx.index("Filtres WAF") < idx.index("Émissions") < idx.index("'code'")
    assert (rel / "emissions_relais.py").is_file() and (rel / "emissions.html").is_file()
    assert (home / ".local/lib/secubox-ai-emissions/src/emissions/app.py").is_file()
    assert "IPAddressAllow=192.0.2.10" in (home / ".config/systemd/user/secubox-ai-emissions.service.d/reseau.conf").read_text()
    assert (home / ".config/secubox-ai-emissions/noms-internes.txt").stat().st_mode & 0o077 == 0
