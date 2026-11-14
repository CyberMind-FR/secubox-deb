# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Modèles de texte (#3583, tâche 12) : catalogue, installés, téléchargement Hugging Face, activation, suppression.

Fichiers `<etat>/modeles/*.gguf` ; liens symboliques refusés à la liste comme à l'activation. Tout accès à Hugging Face
passe par la garde SSRF de `recherche` (connexion épinglée, adresses publiques, redirections revérifiées à chaque saut :
le CDN de Hugging Face est atteint par redirection). Le fichier est écrit en flux dans `<nom>.part`, empreinte SHA-256
calculée au fil de l'eau, jamais chargé en mémoire. Le journal ne reçoit ni adresse ni dépôt.
"""
import hashlib
import json
import os
import re
import shutil
import tempfile
from datetime import date

from fastapi import APIRouter, BackgroundTasks, Body, Depends, HTTPException

from api import moteurs, recherche, reglages
from api.journal import journal
from secubox_core.auth import require_jwt

PLANCHER_DISQUE = 5 * 1024**3
DEPOT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,80}/[A-Za-z0-9][A-Za-z0-9._-]{0,100}$")
DELAI_TELECHARGEMENT_S = 120       # délai de lecture entre deux blocs (pas durée totale)
API_HF_MAX = 5 * 1024**2           # réponse JSON de l'API Hugging Face
telechargements: dict = {}         # nom -> {"recu", "total"[, "erreur"]} : suivi en mémoire, exposé par GET /modeles

# Suggestions seulement : la taille et la licence font foi au moment du téléchargement, lues sur le dépôt.
# Les projecteurs `mmproj` du POC ne sont pas repris : l'étape 1 ne lit pas les images.
CATALOGUE = [
    {"nom": "Llama 3.2 1B", "depot": "bartowski/Llama-3.2-1B-Instruct-GGUF", "fichier": "Llama-3.2-1B-Instruct-Q4_K_M.gguf", "mo": 770, "licence": "llama3.2"},
    {"nom": "Phi-4 mini", "depot": "bartowski/microsoft_Phi-4-mini-instruct-GGUF", "fichier": "microsoft_Phi-4-mini-instruct-Q4_K_M.gguf", "mo": 2376, "licence": "à lire sur le dépôt"},
    {"nom": "Gemma 3 4B", "depot": "bartowski/google_gemma-3-4b-it-GGUF", "fichier": "google_gemma-3-4b-it-Q4_K_M.gguf", "mo": 2374, "licence": "à lire sur le dépôt"},
    {"nom": "Mistral 7B", "depot": "bartowski/Mistral-7B-Instruct-v0.3-GGUF", "fichier": "Mistral-7B-Instruct-v0.3-Q4_K_M.gguf", "mo": 4170, "licence": "apache-2.0"},
    {"nom": "Llama 3.1 8B", "depot": "bartowski/Meta-Llama-3.1-8B-Instruct-GGUF", "fichier": "Meta-Llama-3.1-8B-Instruct-Q4_K_M.gguf", "mo": 4692, "licence": "llama3.1"},
    {"nom": "Kev 4B (récent)", "depot": "ggml-org/Kev-4B-GGUF", "fichier": "Kev-4B-Q4_K_M.gguf", "mo": 2870, "licence": "apache-2.0"},
    {"nom": "Ministral 3 3B", "depot": "ggml-org/Ministral-3-3B-Instruct-2512-GGUF", "fichier": "Ministral-3-3B-Instruct-2512-Q8_0.gguf", "mo": 3480, "licence": "apache-2.0"},
    {"nom": "Ministral 3 3B raisonnement", "depot": "ggml-org/Ministral-3-3B-Reasoning-2512-GGUF", "fichier": "Ministral-3-3B-Reasoning-2512-Q8_0.gguf", "mo": 3480, "licence": "apache-2.0"},
    {"nom": "Kev 9B (récent)", "depot": "ggml-org/Kev-9B-GGUF", "fichier": "Kev-9B-Q4_K_M.gguf", "mo": 6040, "licence": "apache-2.0"},
    {"nom": "Clef Flash", "depot": "ggml-org/Clef-Flash-GGUF", "fichier": "Clef-Flash-Q4_K_M.gguf", "mo": 6350, "licence": "apache-2.0"},
    {"nom": "Ministral 3 8B", "depot": "ggml-org/Ministral-3-8B-Instruct-2512-GGUF", "fichier": "Ministral-3-8B-Instruct-2512-Q8_0.gguf", "mo": 8600, "licence": "apache-2.0"},
    {"nom": "GPT-OSS 20B", "depot": "ggml-org/gpt-oss-20b-GGUF", "fichier": "gpt-oss-20b-MXFP4.gguf", "mo": 11548, "licence": "apache-2.0"},
    # Qwen 3.5 9B distillé des réponses de DeepSeek-V4-Pro (Jackrong) ; « heretic » = refus retirés (xtools-at).
    {"nom": "DeepSeek-V4-Pro Qwen3.5 9B non censuré", "depot": "Sakura721/DeepSeek-V4-Pro-Qwen3.5-9B-UNCENSORED-heretic-GGUF", "fichier": "DeepSeek-V4-Pro-Qwen3.5-9B-UNCENSORED-heretic-Q4_K_M.gguf", "mo": 5368, "licence": "apache-2.0"},
    {"nom": "DeepSeek-V4-Pro Qwen3.5 9B non censuré (Q5)", "depot": "mradermacher/DeepSeek-V4-Pro-Qwen3.5-9B-UNCENSORED-heretic-GGUF", "fichier": "DeepSeek-V4-Pro-Qwen3.5-9B-UNCENSORED-heretic.Q5_K_M.gguf", "mo": 6168, "licence": "apache-2.0"},
    {"nom": "DeepSeek-V4-Pro Qwen3.5 9B", "depot": "mradermacher/DeepSeek-V4-Pro-Qwen3.5-9B-GGUF", "fichier": "DeepSeek-V4-Pro-Qwen3.5-9B.Q4_K_M.gguf", "mo": 5512, "licence": "apache-2.0"},
    # Ajouts du 2026-11-12 : dépôts, fichiers, tailles et licences lus sur l'API Hugging Face le jour même (non restreints).
    {"nom": "Qwen3 0.6B", "depot": "bartowski/Qwen_Qwen3-0.6B-GGUF", "fichier": "Qwen_Qwen3-0.6B-Q4_K_M.gguf", "mo": 484, "licence": "à lire sur le dépôt"},
    {"nom": "Qwen3 1.7B", "depot": "bartowski/Qwen_Qwen3-1.7B-GGUF", "fichier": "Qwen_Qwen3-1.7B-Q4_K_M.gguf", "mo": 1282, "licence": "à lire sur le dépôt"},
    {"nom": "Qwen3 4B", "depot": "bartowski/Qwen_Qwen3-4B-GGUF", "fichier": "Qwen_Qwen3-4B-Q4_K_M.gguf", "mo": 2497, "licence": "à lire sur le dépôt"},
    {"nom": "Qwen3 8B", "depot": "bartowski/Qwen_Qwen3-8B-GGUF", "fichier": "Qwen_Qwen3-8B-Q4_K_M.gguf", "mo": 5028, "licence": "apache-2.0"},
    {"nom": "Qwen3 14B", "depot": "bartowski/Qwen_Qwen3-14B-GGUF", "fichier": "Qwen_Qwen3-14B-Q4_K_M.gguf", "mo": 9002, "licence": "à lire sur le dépôt"},
    {"nom": "Qwen3 30B-A3B (MoE, 32 Go conseillés)", "depot": "bartowski/Qwen_Qwen3-30B-A3B-GGUF", "fichier": "Qwen_Qwen3-30B-A3B-Q4_K_M.gguf", "mo": 18632, "licence": "apache-2.0"},
    {"nom": "Gemma 3 1B", "depot": "bartowski/google_gemma-3-1b-it-GGUF", "fichier": "google_gemma-3-1b-it-Q4_K_M.gguf", "mo": 806, "licence": "gemma"},
    {"nom": "Gemma 3 12B", "depot": "bartowski/google_gemma-3-12b-it-GGUF", "fichier": "google_gemma-3-12b-it-Q4_K_M.gguf", "mo": 7301, "licence": "gemma"},
    {"nom": "Gemma 3n E4B", "depot": "unsloth/gemma-3n-E4B-it-GGUF", "fichier": "gemma-3n-E4B-it-Q4_K_M.gguf", "mo": 4539, "licence": "gemma"},
    {"nom": "Gemma 3 4B non censuré (abliterated)", "depot": "mlabonne/gemma-3-4b-it-abliterated-GGUF", "fichier": "gemma-3-4b-it-abliterated.q4_k_m.gguf", "mo": 2490, "licence": "gemma"},
    {"nom": "Gemma 3 12B non censuré (abliterated)", "depot": "mlabonne/gemma-3-12b-it-abliterated-GGUF", "fichier": "gemma-3-12b-it-abliterated.q4_k_m.gguf", "mo": 7301, "licence": "gemma"},
    {"nom": "Phi-4 14B", "depot": "bartowski/phi-4-GGUF", "fichier": "phi-4-Q4_K_M.gguf", "mo": 9053, "licence": "mit"},
    {"nom": "Phi-4 mini raisonnement", "depot": "bartowski/microsoft_Phi-4-mini-reasoning-GGUF", "fichier": "microsoft_Phi-4-mini-reasoning-Q4_K_M.gguf", "mo": 2492, "licence": "mit"},
    {"nom": "DeepSeek-R1 distillé Qwen 7B", "depot": "bartowski/DeepSeek-R1-Distill-Qwen-7B-GGUF", "fichier": "DeepSeek-R1-Distill-Qwen-7B-Q4_K_M.gguf", "mo": 4683, "licence": "à lire sur le dépôt"},
    {"nom": "DeepSeek-R1 distillé Qwen 14B", "depot": "bartowski/DeepSeek-R1-Distill-Qwen-14B-GGUF", "fichier": "DeepSeek-R1-Distill-Qwen-14B-Q4_K_M.gguf", "mo": 8988, "licence": "à lire sur le dépôt"},
    {"nom": "Qwen2.5 Coder 7B", "depot": "bartowski/Qwen2.5-Coder-7B-Instruct-GGUF", "fichier": "Qwen2.5-Coder-7B-Instruct-Q4_K_M.gguf", "mo": 4683, "licence": "apache-2.0"},
    {"nom": "Qwen2.5 Coder 14B", "depot": "bartowski/Qwen2.5-Coder-14B-Instruct-GGUF", "fichier": "Qwen2.5-Coder-14B-Instruct-Q4_K_M.gguf", "mo": 8988, "licence": "apache-2.0"},
    {"nom": "SmolLM3 3B", "depot": "bartowski/HuggingFaceTB_SmolLM3-3B-GGUF", "fichier": "HuggingFaceTB_SmolLM3-3B-Q4_K_M.gguf", "mo": 1915, "licence": "apache-2.0"},
    {"nom": "Granite 3.3 8B", "depot": "bartowski/ibm-granite_granite-3.3-8b-instruct-GGUF", "fichier": "ibm-granite_granite-3.3-8b-instruct-Q4_K_M.gguf", "mo": 4943, "licence": "apache-2.0"},
    {"nom": "Mistral Nemo 12B", "depot": "bartowski/Mistral-Nemo-Instruct-2407-GGUF", "fichier": "Mistral-Nemo-Instruct-2407-Q4_K_M.gguf", "mo": 7477, "licence": "apache-2.0"},
    {"nom": "Mistral Small 3.2 24B", "depot": "bartowski/mistralai_Mistral-Small-3.2-24B-Instruct-2506-GGUF", "fichier": "mistralai_Mistral-Small-3.2-24B-Instruct-2506-Q4_K_M.gguf", "mo": 14334, "licence": "apache-2.0"},
    {"nom": "Hermes 3 Llama 3.1 8B", "depot": "NousResearch/Hermes-3-Llama-3.1-8B-GGUF", "fichier": "Hermes-3-Llama-3.1-8B.Q4_K_M.gguf", "mo": 4921, "licence": "llama3"},
    {"nom": "Llama 3.2 3B", "depot": "bartowski/Llama-3.2-3B-Instruct-GGUF", "fichier": "Llama-3.2-3B-Instruct-Q4_K_M.gguf", "mo": 2019, "licence": "llama3.2"},
]


def nom_valide(nom) -> bool:
    """`[A-Za-z0-9._-]+.gguf` : ni `/`, ni `..`, ni point initial (la regex de reglages l'impose déjà)."""
    return isinstance(nom, str) and bool(reglages.NOM_MODELE.match(nom)) and ".." not in nom


def genre_fichier(nom) -> str:
    """Dans un dépôt, tout .gguf n'est pas un modèle à charger seul."""
    if re.search(r"(^|[-_])(mmproj|mtp|dflash|eagle\d*|lilicorr|draft)[-_]", nom, re.I):
        return "annexe"
    if re.search(r"-\d{5}-of-\d{5}\.gguf$", nom):
        return "decoupe"
    return "modele"


def _fichiers() -> dict:
    """Liste blanche : les modèles réellement présents (fichiers réguliers, ni lien ni nom douteux)."""
    sortie = {}
    try:
        for f in sorted(reglages.modeles_dir().glob("*.gguf")):
            if nom_valide(f.name) and not f.is_symlink() and f.is_file() and genre_fichier(f.name) == "modele":
                sortie[f.name] = f
    except OSError:
        pass
    return sortie


def _fiche(f) -> dict:
    infos = {}
    meta = f.with_suffix(".json")
    try:
        if meta.is_file() and not meta.is_symlink():
            lu = json.loads(meta.read_text(encoding="utf-8"))
            if isinstance(lu, dict):
                infos = lu
    except (OSError, ValueError):
        pass
    # Étape 1 : texte seulement (aucun projecteur `--mmproj` n'est chargé par le contrôleur).
    return {**infos, "id": f.name, "taille": f.stat().st_size, "medias": ["texte"]}


def _en_cours(nom) -> bool:
    return nom in telechargements and "erreur" not in telechargements[nom]


def _dossier(creer=False):
    d = reglages.modeles_dir()
    if creer:
        d.mkdir(mode=0o750, parents=True, exist_ok=True)
    return d


async def _json_hf(url: str) -> dict:
    """Réponse JSON de l'API Hugging Face, lue par la garde SSRF (fichier temporaire borné, jamais en mémoire entière
    avant le contrôle de taille). 404 si le dépôt n'existe pas ou est réservé ; 502 si Hugging Face est injoignable."""
    d = _dossier(creer=True)
    fd, tmp = tempfile.mkstemp(dir=d, prefix=".api-", suffix=".tmp")
    os.close(fd)
    try:
        try:
            await recherche.telecharger_fichier(url, tmp, API_HF_MAX, delai=20)
        except HTTPException as e:
            if e.status_code == 502 and re.search(r"\b(401|403|404)$", str(e.detail)):
                raise HTTPException(404, "dépôt introuvable ou réservé") from None
            if e.status_code == 502:
                raise HTTPException(502, "Hugging Face injoignable depuis ce poste (réseau ou DNS)") from None
            raise HTTPException(502, "réponse de Hugging Face refusée") from None
        try:
            with open(tmp, encoding="utf-8") as f:
                return json.load(f)
        except (OSError, ValueError):
            raise HTTPException(502, "réponse de Hugging Face illisible") from None
    finally:
        try:
            os.unlink(tmp)
        except OSError:
            pass


async def infos_depot(depot: str) -> dict:
    if not DEPOT.match(depot):
        raise HTTPException(422, "dépôt invalide (éditeur/nom)")
    d = await _json_hf(f"https://huggingface.co/api/models/{depot}?blobs=true")
    if not isinstance(d, dict):
        raise HTTPException(502, "réponse de Hugging Face illisible")
    fichiers = []
    for s in d.get("siblings") or []:
        nom = s.get("rfilename") if isinstance(s, dict) else None
        if isinstance(nom, str) and nom.endswith(".gguf") and "/" not in nom:
            lfs = s.get("lfs") if isinstance(s.get("lfs"), dict) else {}
            fichiers.append({"nom": nom, "taille": s.get("size"), "sha256": lfs.get("sha256"), "genre": genre_fichier(nom)})
    carte = d.get("cardData") if isinstance(d.get("cardData"), dict) else {}
    return {"depot": depot, "licence": carte.get("license"), "restreint": bool(d.get("gated")), "fichiers": fichiers}


async def telecharger(depot, nom, sha, taille, licence):
    """Télécharge `nom` dans `<nom>.part` (flux, empreinte au fil de l'eau) puis le renomme.
    Empreinte différente : le fichier devient `<nom>.faux` et la fonction lève HTTPException(409).
    Autre échec (GGUF invalide, garde SSRF, réseau, taille) : le `.part` est effacé, HTTPException levée."""
    d = _dossier(creer=True)
    final, part, faux = d / nom, d / (nom + ".part"), d / (nom + ".faux")
    suivi = telechargements.setdefault(nom, {"recu": 0, "total": taille})
    empreinte = hashlib.sha256()

    def progres(n):
        suivi["recu"] = n

    try:
        await recherche.telecharger_fichier(f"https://huggingface.co/{depot}/resolve/main/{nom}", part, taille,
                                            delai=DELAI_TELECHARGEMENT_S, empreinte=empreinte, progres=progres)
        if empreinte.hexdigest() != str(sha).lower():
            faux.unlink(missing_ok=True)
            os.replace(part, faux)          # gardé pour examen, jamais listé ni activable
            raise HTTPException(409, "empreinte SHA-256 différente : fichier mis de côté (.faux)")
        with open(part, "rb") as f:
            if f.read(4) != b"GGUF":
                raise HTTPException(422, "ce n'est pas un fichier GGUF")
        os.replace(part, final)
        meta = final.with_suffix(".json")
        tmp = meta.with_suffix(".json.tmp")
        tmp.write_text(json.dumps({"depot": depot, "licence": licence, "sha256": str(sha).lower(),
                                   "ajoute": date.today().isoformat()}, ensure_ascii=False), encoding="utf-8")
        os.replace(tmp, meta)
        journal("modele.ajout", modele=nom, licence=licence if isinstance(licence, str) else None)
        telechargements.pop(nom, None)
    except HTTPException:
        part.unlink(missing_ok=True)
        raise
    except OSError:
        part.unlink(missing_ok=True)
        raise HTTPException(500, "écriture impossible") from None


async def _lancer(depot, nom, sha, taille, licence):
    """Tâche de fond : l'échec est consigné dans le suivi (affiché par la page) et au journal, sans adresse."""
    try:
        await telecharger(depot, nom, sha, taille, licence)
    except HTTPException as e:
        telechargements.setdefault(nom, {"recu": 0, "total": taille})["erreur"] = str(e.detail)[:200]
        journal("modele.echec", modele=nom, code=e.status_code, cause=str(e.detail)[:200])


def _modele(nom) -> object:
    f = _fichiers().get(nom) if nom_valide(nom) else None
    if f is None:
        raise HTTPException(404, "modèle inconnu")
    return f


routeur = APIRouter(prefix="")


@routeur.get("/modeles/catalogue", dependencies=[Depends(require_jwt)])
async def get_catalogue():
    return {"catalogue": CATALOGUE}


@routeur.get("/modeles", dependencies=[Depends(require_jwt)])
async def get_modeles():
    return {"actif": reglages.lire_prefs()["moteur"]["modele"],
            "modeles": [_fiche(f) for f in _fichiers().values()], "telechargements": telechargements}


@routeur.get("/modeles/depot", dependencies=[Depends(require_jwt)])
async def get_depot(depot: str):
    return await infos_depot(depot)


@routeur.post("/modeles", dependencies=[Depends(require_jwt)])
async def post_modele(taches: BackgroundTasks, corps: dict = Body(...)):
    depot, nom = str(corps.get("depot", "")), str(corps.get("fichier", ""))
    if not DEPOT.match(depot) or not nom_valide(nom):
        raise HTTPException(422, "dépôt ou fichier invalide")
    if (_dossier() / nom).exists() or _en_cours(nom):
        raise HTTPException(409, "déjà présent ou en cours")
    infos = await infos_depot(depot)
    choix = next((f for f in infos["fichiers"] if f["nom"] == nom), None)
    if choix and choix["genre"] != "modele":
        raise HTTPException(422, "fichier annexe ou modèle découpé : non installable seul")
    if (not choix or not isinstance(choix["sha256"], str) or not re.fullmatch(r"[0-9a-fA-F]{64}", choix["sha256"])
            or not isinstance(choix["taille"], int) or isinstance(choix["taille"], bool) or choix["taille"] <= 0):
        raise HTTPException(422, "fichier absent du dépôt, ou sans empreinte vérifiable")
    if infos["restreint"]:
        raise HTTPException(403, "dépôt réservé : conditions à accepter chez l'éditeur")
    if shutil.disk_usage(_dossier(creer=True)).free - choix["taille"] < PLANCHER_DISQUE:
        raise HTTPException(507, "place insuffisante : 5 Gio doivent rester libres")
    telechargements[nom] = {"recu": 0, "total": choix["taille"]}
    taches.add_task(_lancer, depot, nom, choix["sha256"], choix["taille"], infos["licence"])
    return {"ok": True}


@routeur.post("/modeles/{nom}/activer", dependencies=[Depends(require_jwt)])
async def activer(nom: str):
    """Écrit la préférence, puis, si le moteur local tourne, le redémarre sur ce modèle et attend qu'il réponde.
    Refus mémoire ou erreur du contrôleur : 503 avec son message (la préférence reste écrite)."""
    _modele(nom)
    reglages.ecrire_prefs(reglages.valider({"moteur": {"modele": nom}}))
    journal("modele.activer", modele=nom)
    if await moteurs._sonde(moteurs._local(), 2):
        await moteurs.changer_modele_local()
    return {"ok": True}


@routeur.delete("/modeles/{nom}", dependencies=[Depends(require_jwt)])
async def supprimer(nom: str):
    f = _modele(nom)
    if reglages.lire_prefs()["moteur"]["modele"] == nom:
        raise HTTPException(409, "modèle actif : en activer un autre d'abord")
    f.unlink()
    f.with_suffix(".json").unlink(missing_ok=True)
    journal("modele.suppression", modele=nom)
    return {"ok": True}
