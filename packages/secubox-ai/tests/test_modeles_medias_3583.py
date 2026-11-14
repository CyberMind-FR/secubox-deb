# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Modèles, médias, journal (#3583, tâche 12). Aucun réseau réel : Hugging Face simulé par un transport httpx."""
import asyncio
import hashlib
import json

import httpx
import pytest
from fastapi import HTTPException

from secubox_core.auth import require_jwt

from api import journal as jrn
from api import medias, modeles, moteurs, recherche, reglages
from api.main import app

CONTENU = b"GGUF" + b"\x00" * 4096
SHA = hashlib.sha256(CONTENU).hexdigest()
NOM = "petit-q4.gguf"
DEPOT = "editeur/petit-GGUF"
PNG = b"\x89PNG\r\n\x1a\n" + b"\x00" * 100


@pytest.fixture
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("SECUBOX_AI_ETAT", str(tmp_path / "etat"))
    monkeypatch.setenv("SECUBOX_AI_CONF", str(tmp_path / "ai.toml"))
    monkeypatch.setenv("SECUBOX_AI_CLE", str(tmp_path / "cle"))
    monkeypatch.setenv("SECUBOX_AI_RUN", str(tmp_path / "run"))
    (tmp_path / "run" / "demandes").mkdir(parents=True)       # créé par secubox-aictl preparer en production
    modeles.telechargements.clear()
    app.dependency_overrides[require_jwt] = lambda: {"sub": "admin"}
    yield tmp_path
    app.dependency_overrides.pop(require_jwt, None)
    modeles.telechargements.clear()


@pytest.fixture
def hf(env, monkeypatch):
    """Hugging Face simulé : API du dépôt, fichier servi par redirection vers un CDN. Résolveur injecté."""
    etat = {"vues": [], "contenu": CONTENU, "sha": SHA, "taille": len(CONTENU), "gated": False,
            "dns": {}, "cdn": "https://cdn.exemple.test/blob/abc"}

    def handler(req):
        origine = f"{req.url.scheme}://{req.headers['host']}{req.url.raw_path.decode()}"
        etat["vues"].append(origine)
        if origine.startswith(f"https://huggingface.co/api/models/{DEPOT}"):
            return httpx.Response(200, json={"cardData": {"license": "mit"}, "gated": etat["gated"], "siblings": [
                {"rfilename": NOM, "size": etat["taille"], "lfs": {"sha256": etat["sha"]}},
                {"rfilename": "mmproj-petit.gguf", "size": 10, "lfs": {"sha256": "0" * 64}},
                {"rfilename": "README.md"}]})
        if origine == f"https://huggingface.co/{DEPOT}/resolve/main/{NOM}":
            return httpx.Response(302, headers={"location": etat["cdn"]})
        if origine == etat["cdn"]:
            return httpx.Response(200, content=etat["contenu"])
        return httpx.Response(404)

    async def resolveur(hote):
        return etat["dns"].get(hote, ["93.184.216.34"])

    inet6 = env / "if_inet6"
    inet6.write_text("", encoding="ascii")
    monkeypatch.setattr(recherche, "SOURCE_IF_INET6", str(inet6))
    monkeypatch.setattr(recherche, "FABRIQUE_TRANSPORT_WEB", lambda nom: httpx.MockTransport(handler))
    monkeypatch.setattr(recherche, "RESOLVEUR", resolveur)
    monkeypatch.setattr(modeles, "PLANCHER_DISQUE", 0)
    return etat


def client():
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t")


def installer(env, nom=NOM, contenu=CONTENU):
    d = env / "etat" / "modeles"
    d.mkdir(parents=True, exist_ok=True)
    (d / nom).write_bytes(contenu)
    return d / nom


# ---------------- noms ----------------
@pytest.mark.parametrize("nom", ["../x.gguf", "a/b.gguf", "a..b.gguf", ".cache.gguf", "x.bin", "x.gguf/", "", "é.gguf",
                                 "x" * 200 + ".gguf", "a b.gguf"])
def test_nom_de_modele_refuse(nom):
    assert not modeles.nom_valide(nom)


def test_nom_de_modele_accepte():
    assert modeles.nom_valide("Qwen_Qwen3-4B-Q4_K_M.gguf") and modeles.nom_valide("a.b-c_d.gguf")


@pytest.mark.asyncio
async def test_routes_refusent_un_nom_douteux(env, hf):
    installer(env)
    async with client() as c:
        assert (await c.post("/modeles", json={"depot": DEPOT, "fichier": "../etc.gguf"})).status_code == 422
        assert (await c.post("/modeles", json={"depot": DEPOT, "fichier": "a/b.gguf"})).status_code == 422
        assert (await c.post("/modeles", json={"depot": "../x", "fichier": NOM})).status_code == 422
        assert (await c.post("/modeles/a..b.gguf/activer")).status_code == 404
        assert (await c.post("/modeles/..%2Fx.gguf/activer")).status_code == 404
        assert (await c.delete("/modeles/a..b.gguf")).status_code == 404
    assert hf["vues"] == []


# ---------------- liste, liens, annexes ----------------
@pytest.mark.asyncio
async def test_liste_sans_liens_ni_annexes(env):
    d = installer(env).parent
    (d / "mmproj-x-f16.gguf").write_bytes(b"GGUF")
    (d / "gros-00001-of-00002.gguf").write_bytes(b"GGUF")
    (d / "x.gguf.part").write_bytes(b"GG")
    (d / "x.gguf.faux").write_bytes(b"GG")
    cible = env / "secret.gguf"
    cible.write_bytes(b"GGUF")
    (d / "lien.gguf").symlink_to(cible)
    (d / "petit-q4.json").write_text(json.dumps({"licence": "mit", "depot": "e/p"}))
    async with client() as c:
        r = (await c.get("/modeles")).json()
    assert [m["id"] for m in r["modeles"]] == [NOM]
    assert r["modeles"][0]["licence"] == "mit" and r["modeles"][0]["medias"] == ["texte"]
    assert r["actif"] == reglages.DEFAUTS["moteur"]["modele"] and r["telechargements"] == {}


@pytest.mark.asyncio
async def test_catalogue_sans_projecteur(env):
    async with client() as c:
        cat = (await c.get("/modeles/catalogue")).json()["catalogue"]
    assert len(cat) > 30 and all(modeles.nom_valide(m["fichier"]) and modeles.DEPOT.match(m["depot"]) for m in cat)
    assert all("mmproj" not in m for m in cat)


# ---------------- téléchargement ----------------
@pytest.mark.asyncio
async def test_empreinte_fausse_fichier_faux_et_409(env, hf):
    d = env / "etat" / "modeles"
    with pytest.raises(HTTPException) as e:
        await modeles.telecharger(DEPOT, NOM, "0" * 64, len(CONTENU), "mit")
    assert e.value.status_code == 409
    assert (d / (NOM + ".faux")).read_bytes() == CONTENU
    assert not (d / NOM).exists() and not (d / (NOM + ".part")).exists()
    async with client() as c:
        assert (await c.get("/modeles")).json()["modeles"] == []
        assert (await c.post(f"/modeles/{NOM}/activer")).status_code == 404


@pytest.mark.asyncio
async def test_telechargement_bon_par_la_route(env, hf):
    d = env / "etat" / "modeles"
    async with client() as c:
        assert (await c.get(f"/modeles/depot?depot={DEPOT}")).json()["fichiers"][0]["genre"] == "modele"
        r = await c.post("/modeles", json={"depot": DEPOT, "fichier": NOM})
        assert r.status_code == 200
        m = (await c.get("/modeles")).json()
    assert (d / NOM).read_bytes() == CONTENU and not (d / (NOM + ".part")).exists()
    assert [x["id"] for x in m["modeles"]] == [NOM] and m["modeles"][0]["sha256"] == SHA
    assert m["telechargements"] == {}
    assert "https://cdn.exemple.test/blob/abc" in hf["vues"]      # redirection suivie, saut revérifié
    assert any(x["action"] == "modele.ajout" for x in jrn.lire())


@pytest.mark.asyncio
async def test_route_echec_empreinte_suivi_et_journal(env, hf):
    hf["sha"] = "f" * 64
    async with client() as c:
        assert (await c.post("/modeles", json={"depot": DEPOT, "fichier": NOM})).status_code == 200
        m = (await c.get("/modeles")).json()
    assert m["modeles"] == [] and "empreinte" in m["telechargements"][NOM]["erreur"]
    assert (env / "etat" / "modeles" / (NOM + ".faux")).exists()
    assert any(x["action"] == "modele.echec" and x["code"] == 409 for x in jrn.lire())


@pytest.mark.asyncio
async def test_redirection_vers_adresse_privee_refusee(env, hf):
    hf["cdn"] = "https://cdn.exemple.test/blob/abc"
    hf["dns"]["cdn.exemple.test"] = ["10.0.0.5"]
    with pytest.raises(HTTPException) as e:
        await modeles.telecharger(DEPOT, NOM, SHA, len(CONTENU), "mit")
    assert e.value.status_code == 422
    assert not list((env / "etat" / "modeles").glob(NOM + "*"))
    assert "https://cdn.exemple.test/blob/abc" not in hf["vues"]


@pytest.mark.asyncio
async def test_hf_sur_adresse_privee_refuse_aucune_requete(env, hf):
    hf["dns"]["huggingface.co"] = ["127.0.0.1"]
    async with client() as c:
        r = await c.get(f"/modeles/depot?depot={DEPOT}")
    assert r.status_code == 502 and hf["vues"] == []


@pytest.mark.asyncio
async def test_fichier_plus_gros_qu_annonce_et_non_gguf(env, hf):
    d = env / "etat" / "modeles"
    hf["contenu"] = CONTENU + b"x" * 10
    with pytest.raises(HTTPException) as e:
        await modeles.telecharger(DEPOT, NOM, SHA, len(CONTENU), "mit")
    assert e.value.status_code == 413 and not list(d.glob(NOM + "*"))
    faux = b"PK\x03\x04" + b"\x00" * 100
    hf["contenu"] = faux
    with pytest.raises(HTTPException) as e:
        await modeles.telecharger(DEPOT, NOM, hashlib.sha256(faux).hexdigest(), len(faux), "mit")
    assert e.value.status_code == 422 and not list(d.glob(NOM + "*"))


@pytest.mark.asyncio
async def test_refus_depot_reserve_annexe_inconnu_disque(env, hf, monkeypatch):
    async with client() as c:
        assert (await c.post("/modeles", json={"depot": DEPOT, "fichier": "mmproj-petit.gguf"})).status_code == 422
        assert (await c.post("/modeles", json={"depot": DEPOT, "fichier": "absent.gguf"})).status_code == 422
        hf["gated"] = True
        assert (await c.post("/modeles", json={"depot": DEPOT, "fichier": NOM})).status_code == 403
        hf["gated"] = False
        monkeypatch.setattr(modeles, "PLANCHER_DISQUE", 10**18)
        assert (await c.post("/modeles", json={"depot": DEPOT, "fichier": NOM})).status_code == 507
        monkeypatch.setattr(modeles, "PLANCHER_DISQUE", 0)
        installer(env)
        assert (await c.post("/modeles", json={"depot": DEPOT, "fichier": NOM})).status_code == 409


@pytest.mark.asyncio
async def test_journal_sans_depot_ni_adresse(env, hf):
    hf["sha"] = "f" * 64
    async with client() as c:
        await c.post("/modeles", json={"depot": DEPOT, "fichier": NOM})
    brut = (env / "etat" / "journal.jsonl").read_text(encoding="utf-8")
    assert "editeur" not in brut and "huggingface" not in brut and "http" not in brut


# ---------------- activation, suppression, R6 ----------------
@pytest.mark.asyncio
async def test_activation_ecrit_la_preference_sans_moteur_local(env, monkeypatch):
    installer(env)

    async def pas_de_moteur(m, delai):
        return False

    appels = []
    monkeypatch.setattr(moteurs, "_sonde", pas_de_moteur)
    monkeypatch.setattr(moteurs, "changer_modele_local", lambda *a, **k: appels.append(1))
    async with client() as c:
        assert (await c.post(f"/modeles/{NOM}/activer")).status_code == 200
        assert (await c.get("/modeles")).json()["actif"] == NOM
    assert appels == []


@pytest.mark.asyncio
async def test_activation_redemarre_le_moteur_local(env, monkeypatch):
    installer(env)
    appels = []

    async def pret(m, delai):
        return True

    async def changer(*a, **k):
        appels.append(reglages.lire_prefs()["moteur"]["modele"])       # la préférence est écrite avant l'appel

    monkeypatch.setattr(moteurs, "_sonde", pret)
    monkeypatch.setattr(moteurs, "changer_modele_local", changer)
    async with client() as c:
        assert (await c.post(f"/modeles/{NOM}/activer")).status_code == 200
    assert appels == [NOM]


@pytest.mark.asyncio
async def test_activation_rapporte_le_refus_du_controleur(env, monkeypatch):
    installer(env)

    async def pret(m, delai):
        return True

    async def refus(*a, **k):
        raise HTTPException(503, "mémoire insuffisante pour ce modèle")

    monkeypatch.setattr(moteurs, "_sonde", pret)
    monkeypatch.setattr(moteurs, "changer_modele_local", refus)
    async with client() as c:
        r = await c.post(f"/modeles/{NOM}/activer")
    assert r.status_code == 503 and "mémoire insuffisante" in r.json()["detail"]


@pytest.mark.asyncio
async def test_activation_refuse_un_lien_symbolique(env):
    d = installer(env).parent
    cible = env / "autre.gguf"
    cible.write_bytes(b"GGUF")
    (d / "lien.gguf").symlink_to(cible)
    async with client() as c:
        assert (await c.post("/modeles/lien.gguf/activer")).status_code == 404
        assert (await c.delete("/modeles/lien.gguf")).status_code == 404
    assert cible.exists()


def test_valider_exige_le_fichier_regulier(env):
    with pytest.raises(HTTPException) as e:
        reglages.valider({"moteur": {"modele": NOM}})
    assert e.value.status_code == 422
    d = installer(env).parent
    assert reglages.valider({"moteur": {"modele": NOM}})["moteur"]["modele"] == NOM
    (d / "lien.gguf").symlink_to(d / NOM)
    with pytest.raises(HTTPException):
        reglages.valider({"moteur": {"modele": "lien.gguf"}})
    # la lecture des préférences, elle, ne l'exige pas
    reglages.ecrire_prefs({**reglages.lire_prefs(), "moteur": {**reglages.lire_prefs()["moteur"], "modele": NOM}})
    (d / NOM).unlink()
    assert reglages.lire_prefs()["moteur"]["modele"] == NOM and reglages.etat_prefs()["erreur"] is None


@pytest.mark.asyncio
async def test_suppression(env):
    d = installer(env).parent
    (d / "petit-q4.json").write_text("{}")
    async with client() as c:
        assert (await c.post(f"/modeles/{NOM}/activer")).status_code in (200, 503)
        assert (await c.delete(f"/modeles/{NOM}")).status_code == 409       # actif
        installer(env, "autre.gguf")
        await c.post("/modeles/autre.gguf/activer")
        assert (await c.delete(f"/modeles/{NOM}")).status_code == 200
        assert (await c.delete(f"/modeles/{NOM}")).status_code == 404
    assert not (d / NOM).exists() and not (d / "petit-q4.json").exists()


# ---------------- journal ----------------
@pytest.mark.parametrize("champ", ["question", "texte", "titre", "url", "reponse", "depot", "cle"])
def test_journal_refuse_les_champs_interdits(env, champ):
    with pytest.raises(ValueError):
        jrn.journal("x.test", **{champ: "contenu"})
    assert not (env / "etat" / "journal.jsonl").exists()


def test_journal_ecrit_et_lit(env):
    jrn.journal("demo.un", n=1, issue="ok")
    jrn.journal("demo.deux", liste=["a", 2])
    (env / "etat" / "journal.jsonl").open("a").write("pas du json\n")
    lignes = jrn.lire()
    assert [x["action"] for x in lignes] == ["demo.deux", "demo.un"] and lignes[1]["n"] == 1
    with pytest.raises(ValueError):
        jrn.journal("Mauvaise action")


@pytest.mark.asyncio
async def test_route_journal(env):
    for i in range(70):
        jrn.journal("demo.ligne", n=i)
    async with client() as c:
        r = (await c.get("/journal")).json()["lignes"]
        assert len(r) == 60 and r[0]["n"] == 69
    assert (env / "etat" / "journal.jsonl").stat().st_mode & 0o077 == 0


@pytest.mark.asyncio
async def test_route_journal_vide(env):
    async with client() as c:
        assert (await c.get("/journal")).json() == {"lignes": []}


# ---------------- médias ----------------
async def deposer(c, octets, **kw):
    return await c.post("/medias/entree", content=octets, **kw)


@pytest.mark.asyncio
async def test_media_depot_liste_service_suppression(env, monkeypatch):
    monkeypatch.setattr(medias, "PLANCHER_DISQUE", 0)
    async with client() as c:
        r = await deposer(c, PNG)
        assert r.status_code == 200
        ident = r.json()["id"]
        liste = (await c.get("/medias/entree")).json()
        assert [m["id"] for m in liste["medias"]] == [ident] and liste["utilise"] == len(PNG) and liste["quota"] == 2 * 1024**3
        assert liste["medias"][0]["analysable"] is True and "ext" not in liste["medias"][0]
        f = await c.get(f"/medias/entree/{ident}/fichier")
        assert f.content == PNG and f.headers["content-type"] == "image/png"
        assert f.headers["x-content-type-options"] == "nosniff" and "inline" in f.headers["content-disposition"]
        assert "attachment" in (await c.get(f"/medias/entree/{ident}/fichier?telecharger=1")).headers["content-disposition"]
        assert (await c.delete(f"/medias/entree/{ident}")).status_code == 200
        assert (await c.get("/medias/entree")).json()["medias"] == []
        assert (await c.get(f"/medias/entree/{ident}/fichier")).status_code == 404
    brut = (env / "etat" / "journal.jsonl").read_text(encoding="utf-8")
    assert ident not in brut and "media.depot" in brut and "media.suppression" in brut


@pytest.mark.asyncio
async def test_media_depot_refus(env, monkeypatch):
    monkeypatch.setattr(medias, "PLANCHER_DISQUE", 0)
    async with client() as c:
        assert (await deposer(c, b"%PDF-1.4" + b"\x00" * 100)).status_code == 415
        assert (await deposer(c, b"")).status_code in (411, 415)
        monkeypatch.setattr(medias, "ENTREE_MAX", 50)
        assert (await deposer(c, PNG)).status_code == 413
        monkeypatch.setattr(medias, "ENTREE_MAX", 50 * 1024**2)
        monkeypatch.setattr(medias, "QUOTA_MEDIAS", 50)
        assert (await deposer(c, PNG)).status_code == 507
        monkeypatch.setattr(medias, "QUOTA_MEDIAS", 2 * 1024**3)
        monkeypatch.setattr(medias, "PLANCHER_DISQUE", 10**18)
        assert (await deposer(c, PNG)).status_code == 507
    d = env / "etat" / "medias" / "entree"
    assert not list(d.glob(".tmp-*")) and not list(d.glob("*.png"))


@pytest.mark.asyncio
async def test_media_dossier_et_identifiant_inconnus(env):
    async with client() as c:
        assert (await c.get("/medias/ailleurs")).status_code == 404
        assert (await c.get("/medias/entree/..%2F..%2Fpreferences/fichier")).status_code == 404
        assert (await c.get("/medias/entree/20260101T000000000000-deadbeef/fichier")).status_code == 404
        assert (await c.delete("/medias/entree/20260101T000000000000-deadbeef")).status_code == 404
        g = (await c.get("/medias/generes")).json()
    assert g["medias"] == [] and g["retires"] == 0
    assert oct((env / "etat" / "medias" / "entree").stat().st_mode & 0o777) == "0o700"


@pytest.mark.asyncio
async def test_media_lien_symbolique_ignore(env, monkeypatch):
    monkeypatch.setattr(medias, "PLANCHER_DISQUE", 0)
    async with client() as c:
        ident = (await deposer(c, PNG)).json()["id"]
        d = env / "etat" / "medias" / "entree"
        secret = env / "secret.png"
        secret.write_bytes(PNG)
        (d / f"{ident}.png").unlink()
        (d / f"{ident}.png").symlink_to(secret)
        assert (await c.get("/medias/entree")).json()["medias"] == []
        assert (await c.get(f"/medias/entree/{ident}/fichier")).status_code == 404


# ---------------- garde d'authentification ----------------
@pytest.mark.asyncio
async def test_toute_route_demande_un_jeton(env):
    app.dependency_overrides.pop(require_jwt, None)
    ident = "20260101T000000000000-deadbeef"
    appels = [("GET", "/modeles"), ("GET", "/modeles/catalogue"), ("GET", f"/modeles/depot?depot={DEPOT}"),
              ("POST", "/modeles"), ("POST", f"/modeles/{NOM}/activer"), ("DELETE", f"/modeles/{NOM}"), ("GET", "/medias/gguf"), ("DELETE", f"/medias/gguf/{NOM}"), ("DELETE", "/medias/gguf-part/x.gguf.part"), ("GET", "/depots"), ("POST", "/depots"), ("DELETE", "/depots/a/b"),
              ("GET", "/medias/entree"), ("GET", f"/medias/entree/{ident}/fichier"),
              ("DELETE", f"/medias/entree/{ident}"), ("POST", "/medias/entree"), ("GET", "/journal")]
    async with client() as c:
        for methode, chemin in appels:
            r = await c.request(methode, chemin, json={} if methode == "POST" else None)
            assert r.status_code in (401, 403), (methode, chemin, r.status_code)


# ---------------- correctifs, tour 1 ----------------
@pytest.mark.asyncio
async def test_gestionnaire_gguf_liste_et_supprime(env):
    d = installer(env).parent
    (d / "mmproj-x-f16.gguf").write_bytes(b"GGUF")
    (d / "x.gguf.faux").write_bytes(b"GG")
    (d / "y.gguf.ab12cd34.part").write_bytes(b"G")
    (d / "z.gguf.part").write_bytes(b"G")
    (d / "lien.gguf.part").symlink_to(env)
    async with client() as c:
        await c.post(f"/modeles/{NOM}/activer")
        r = (await c.get("/medias/gguf")).json()         # déclaré avant /medias/{dossier}
        assert {f["nom"]: f["genre"] for f in r["fichiers"]} == {NOM: "modele", "mmproj-x-f16.gguf": "annexe"}
        assert next(f for f in r["fichiers"] if f["nom"] == NOM)["refus"] and r["disque_libre"] > 0
        assert {p["nom"]: p["genre"] for p in r["parts"]} == {"x.gguf.faux": "faux", "y.gguf.ab12cd34.part": "part", "z.gguf.part": "part"}
        assert (await c.delete(f"/medias/gguf/{NOM}")).status_code == 409           # actif
        assert (await c.delete("/medias/gguf/mmproj-x-f16.gguf")).status_code == 200
        assert (await c.delete("/medias/gguf/../x.gguf")).status_code in (404, 405)
        assert (await c.delete("/medias/gguf-part/x.gguf.faux")).status_code == 200
        assert (await c.delete("/medias/gguf-part/y.gguf.ab12cd34.part")).status_code == 200
        assert (await c.delete("/medias/gguf-part/lien.gguf.part")).status_code == 404
        modeles.telechargements["z.gguf"] = {"recu": 0, "total": 1, "part": "z.gguf.part"}
        assert (await c.delete("/medias/gguf-part/z.gguf.part")).status_code == 409   # en cours
        modeles.telechargements.clear()
        assert (await c.delete("/medias/gguf-part/z.gguf.part")).status_code == 200
    assert (d / NOM).exists() and not (d / "mmproj-x-f16.gguf").exists()


@pytest.mark.asyncio
async def test_depots(env):
    async with client() as c:
        assert (await c.get("/depots")).json() == {"depots": []}
        assert (await c.post("/depots", json={"depot": "../x"})).status_code == 422
        assert (await c.post("/depots", json={"depot": DEPOT})).status_code == 200
        assert (await c.post("/depots", json={"depot": DEPOT})).status_code == 200
        assert (await c.get("/depots")).json() == {"depots": [DEPOT]}
        assert (await c.delete("/depots/editeur/petit-GGUF")).status_code == 200
        assert (await c.get("/depots")).json() == {"depots": []}
    brut = (env / "etat" / "journal.jsonl").read_text(encoding="utf-8")
    assert "depot.ajout" in brut and "depot.retrait" in brut and "editeur" not in brut


@pytest.mark.asyncio
async def test_deux_demandes_simultanees_une_seule_telechargement(env, hf):
    import asyncio
    lancees = []
    vrai = modeles.telecharger

    async def compte(*a):
        lancees.append(1)
        await vrai(*a)

    modeles.telecharger, ancien = compte, modeles.telecharger
    try:
        async with client() as c:
            r = await asyncio.gather(*[c.post("/modeles", json={"depot": DEPOT, "fichier": NOM}) for _ in range(2)])
    finally:
        modeles.telecharger = ancien
    assert sorted(x.status_code for x in r) == [200, 409] and lancees == [1]
    assert (env / "etat" / "modeles" / NOM).read_bytes() == CONTENU
    assert modeles.telechargements == {}


@pytest.mark.asyncio
async def test_refus_libere_la_reservation(env, hf):
    async with client() as c:
        assert (await c.post("/modeles", json={"depot": DEPOT, "fichier": "absent.gguf"})).status_code == 422
        assert modeles.telechargements == {}
        hf["gated"] = True
        assert (await c.post("/modeles", json={"depot": DEPOT, "fichier": NOM})).status_code == 403
        assert modeles.telechargements == {}


@pytest.mark.asyncio
async def test_temporaire_propre_a_chaque_telechargement(env, hf):
    d = env / "etat" / "modeles"
    d.mkdir(parents=True)
    (d / (NOM + ".part")).write_bytes(b"reste d'un ancien telechargement")
    await modeles.telecharger(DEPOT, NOM, SHA, len(CONTENU), "mit")
    assert (d / NOM).read_bytes() == CONTENU and (d / (NOM + ".part")).exists()     # le reste n'est pas touché


@pytest.mark.asyncio
async def test_lancer_marque_l_erreur_sur_toute_exception(env, monkeypatch):
    async def boum(*a):
        raise RuntimeError("inattendu")

    monkeypatch.setattr(modeles, "telecharger", boum)
    modeles.telechargements[NOM] = {"recu": 0, "total": 1}
    await modeles._lancer(DEPOT, NOM, SHA, 1, None)
    assert modeles.telechargements[NOM]["erreur"] and not modeles._en_cours(NOM)

    async def annule(*a):
        raise asyncio.CancelledError()

    monkeypatch.setattr(modeles, "telecharger", annule)
    modeles.telechargements[NOM] = {"recu": 0, "total": 1}
    with pytest.raises(asyncio.CancelledError):
        await modeles._lancer(DEPOT, NOM, SHA, 1, None)
    assert modeles.telechargements[NOM]["erreur"]


@pytest.mark.asyncio
async def test_activation_refusee_retour_arriere(env, monkeypatch):
    installer(env, "ancien.gguf")
    installer(env)
    reglages.ecrire_prefs(reglages.valider({"moteur": {"modele": "ancien.gguf"}}))

    async def pret(m, delai):
        return True

    async def refus(*a, **k):
        raise HTTPException(503, "mémoire insuffisante")

    monkeypatch.setattr(moteurs, "_sonde", pret)
    monkeypatch.setattr(moteurs, "changer_modele_local", refus)
    async with client() as c:
        r = await c.post(f"/modeles/{NOM}/activer")
    assert r.status_code == 503 and "mémoire insuffisante" in r.json()["detail"]
    assert reglages.lire_prefs()["moteur"]["modele"] == "ancien.gguf"
    assert (env / "run" / "demandes" / "demarrer.demande").exists()
    assert [x.get("issue") for x in jrn.lire() if x["action"] == "modele.activer"] == ["refus"]


def test_valider_refuse_annexe_et_decoupe(env):
    d = installer(env).parent
    for n in ("mmproj-x-f16.gguf", "gros-00001-of-00002.gguf"):
        (d / n).write_bytes(b"GGUF")
        with pytest.raises(HTTPException):
            reglages.valider({"moteur": {"modele": n}})


# ---------------- revue finale : modèle téléchargé lisible par le moteur (C2) ----------------
def _aictl():
    import importlib.machinery
    import importlib.util
    import sys
    from pathlib import Path
    if "secubox_aictl_teste" in sys.modules:
        return sys.modules["secubox_aictl_teste"]
    script = Path(__file__).resolve().parents[1] / "sbin" / "secubox-aictl"
    chargeur = importlib.machinery.SourceFileLoader("secubox_aictl_teste", str(script))
    spec = importlib.util.spec_from_loader("secubox_aictl_teste", chargeur)
    mod = importlib.util.module_from_spec(spec)
    sys.modules["secubox_aictl_teste"] = mod
    chargeur.exec_module(mod)
    return mod


@pytest.mark.asyncio
async def test_modele_telecharge_lisible_par_le_moteur(env, hf):
    import os
    import stat
    ancien = os.umask(0o027)              # UMask de secubox-ai.service
    try:
        await modeles.telecharger(DEPOT, NOM, SHA, len(CONTENU), "mit")
    finally:
        os.umask(ancien)
    st = os.stat(env / "etat" / "modeles" / NOM)
    assert stat.S_IMODE(st.st_mode) == 0o640
    # Le moteur n'est pas « autre » : seule la lecture par le groupe secubox-ai (groupe principal de l'API) compte.
    assert _aictl().lisible_par_moteur(st, {"gid_ai": st.st_gid})
