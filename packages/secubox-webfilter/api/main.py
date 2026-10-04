# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""SecuBox WebFilter — API d'observation (#1962, phase 1).

Mode « observe » : ce que le filtrage de contenus AURAIT bloqué, par catégorie et par appareil. Aucune écriture dans Unbound, aucun blocage.
Lecture agrégée (`require_lecture`) ; tout ce qui détaille un appareil ou lance une action exige un administrateur (`require_jwt`).
"""
import copy
import json
import re
import sys
import threading
import time
from pathlib import Path

from fastapi import Depends, FastAPI, HTTPException, Query
from pydantic import BaseModel, ConfigDict, Field
from secubox_core.auth import require_jwt, require_lecture

for _p in ("/usr/lib/secubox/webfilter", str(Path(__file__).resolve().parents[1])):
    if _p not in sys.path:
        sys.path.insert(0, _p)
from webfilter import catalogue, magasin, profils  # noqa: E402
from webfilter import etat as fichiers  # noqa: E402

CATALOGUE = Path("/etc/secubox/webfilter.toml")
ETAT = Path("/var/lib/secubox/webfilter")
JOURS_MAX = 30
DEMANDE = "sync.demande"                                               # surveillé par secubox-webfilter-sync.path
DEMANDE_APPLIQUER = "appliquer.demande"                                # surveillé par secubox-webfilter-apply.path (contrôleur root)
DEMANDE_PERIMEE_S = 600
_MAC = re.compile(r"^[0-9a-f]{2}(:[0-9a-f]{2}){5}$")
_VERROU_CONFIG = threading.Lock()                                      # lecture-modification-écriture de config.json

app = FastAPI(title="SecuBox WebFilter", version="0.1.0")


def _categories() -> list:
    try:
        return catalogue.charger(CATALOGUE)
    except catalogue.ErreurCatalogue as e:
        raise HTTPException(503, f"catalogue illisible : {e}") from None


def _depuis(jours: int) -> str:
    return time.strftime("%Y-%m-%d", time.gmtime(time.time() - (jours - 1) * 86400))


def _meta(cat_id: str, source_nom: str) -> dict:
    try:
        return json.loads((ETAT / "listes" / cat_id / f"{source_nom}.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


@app.get("/health")
def health():
    return {"status": "ok", "module": "webfilter", "version": app.version}


@app.get("/status", dependencies=[Depends(require_lecture)])
@app.get("/etat", dependencies=[Depends(require_lecture)])
def etat():
    """Catalogue, mode et ancienneté des listes ; nombre de requêtes classées sur 7 jours, sans aucun nom d'appareil ni chemin."""
    cats = _categories()
    mag = magasin.Magasin(ETAT / "webfilter.db")
    comptes = mag.par_categorie(_depuis(7))
    decisions = mag.par_categorie_decision(_depuis(7))
    dernier = mag.dernier_evenement()
    sortie = []
    for c in cats:
        srcs = []
        for s in c.sources:
            m = _meta(c.id, s.nom)
            srcs.append({"nom": s.nom, "licence": s.licence, "n": m.get("n"), "ts": m.get("ts")})
        sortie.append({"id": c.id, "libelle": c.libelle, "mode": c.mode, "requetes_7j": comptes.get(c.id, 0),
                       "bloque_7j": decisions.get(c.id, {}).get("bloque", 0), "sources": srcs})
    return {"mode_global": "observe", "categories": sortie,
            "dernier_evenement": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(dernier)) if dernier else None}


@app.get("/stats", dependencies=[Depends(require_jwt)])
def stats(jours: int = Query(7, ge=1, le=JOURS_MAX)):
    m = magasin.Magasin(ETAT / "webfilter.db")
    depuis = _depuis(jours)
    return {"jours": jours, "par_categorie": m.par_categorie(depuis), "par_client": m.par_client(depuis),
            "par_categorie_decision": m.par_categorie_decision(depuis), "par_client_decision": m.par_client_decision(depuis)}


@app.get("/categories/{cat_id}/domaines", dependencies=[Depends(require_jwt)])
def domaines(cat_id: str, jours: int = Query(7, ge=1, le=JOURS_MAX), n: int = Query(50, ge=1, le=500)):
    if cat_id not in {c.id for c in _categories()}:
        raise HTTPException(404, "catégorie inconnue")
    top = magasin.Magasin(ETAT / "webfilter.db").top_domaines(cat_id, _depuis(jours), n)
    return {"categorie": cat_id, "jours": jours, "domaines": [{"domaine": d, "n": c} for d, c in top]}


@app.post("/sync", status_code=202, dependencies=[Depends(require_jwt)])
def sync():
    """Dépose une DEMANDE de synchronisation ; le téléchargement est fait par l'unité systemd secubox-webfilter-sync (jamais dans ce processus)."""
    _categories()                                                       # 503 si le catalogue est illisible
    if not fichiers.deposer(ETAT, DEMANDE, DEMANDE_PERIMEE_S):
        raise HTTPException(409, "une synchronisation est déjà demandée ou en cours")
    return {"statut": "demandee"}


# ── phase 2 : profils, appareils, application ─────────────────────────────────────────────────────────────────────────────────────
class ProfilIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    nom: str = Field(max_length=32)
    categories: dict[str, str] = Field(default_factory=dict, max_length=16)
    autorise: list[str] = Field(default_factory=list, max_length=200)


class AppareilIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    nom: str = Field(default="", max_length=64)
    profil: str = Field(max_length=32)
    exceptions: dict[str, str] = Field(default_factory=dict, max_length=16)


def _ids() -> set:
    try:
        return {c.id for c in catalogue.charger_config(CATALOGUE).categories}
    except catalogue.ErreurCatalogue:
        raise HTTPException(503, "catalogue illisible") from None


def _config(ids: set) -> dict:
    try:
        return fichiers.lire_config(ETAT, ids)
    except profils.ErreurProfils:
        raise HTTPException(503, "configuration des profils illisible") from None


def _enregistrer(cfg: dict, ids: set) -> dict:
    """Valide (422 sinon, rien n'est écrit), incrémente la version, écrit atomiquement."""
    cfg["version"] = cfg.get("version", 0) + 1
    try:
        valide = profils.valider(cfg, ids)
    except profils.ErreurProfils as e:
        raise HTTPException(422, str(e)) from None
    fichiers.ecrire_config(ETAT, valide)
    return valide


def _mac(mac: str) -> str:
    m = mac.lower()
    if not _MAC.match(m):
        raise HTTPException(422, "adresse MAC invalide")
    return m


def _modeles(ids: set) -> dict:
    def garder(d):
        return {c: m for c, m in d.items() if c in ids}
    return {"enfants": {"categories": garder({"adulte": "block", "jeux": "block", "phishing": "block"}), "autorise": []},
            "adultes": {"categories": garder({"phishing": "block"}), "autorise": []}}


@app.get("/profils", dependencies=[Depends(require_jwt)])
def lister_profils():
    ids = _ids()
    cfg = _config(ids)
    return {"version": cfg["version"], "profils": cfg["profils"], "modeles": _modeles(ids)}


@app.post("/profils", dependencies=[Depends(require_jwt)])
def ecrire_profil(corps: ProfilIn):
    ids = _ids()
    with _VERROU_CONFIG:
        cfg = copy.deepcopy(_config(ids))
        cfg["profils"][corps.nom] = {"categories": corps.categories, "autorise": corps.autorise}
        valide = _enregistrer(cfg, ids)
    return {"version": valide["version"], "profils": valide["profils"]}


@app.delete("/profils/{nom}", dependencies=[Depends(require_jwt)])
def supprimer_profil(nom: str):
    ids = _ids()
    with _VERROU_CONFIG:
        cfg = copy.deepcopy(_config(ids))
        if nom not in cfg["profils"]:
            raise HTTPException(404, "profil inconnu")
        if nom == "defaut":
            raise HTTPException(409, "le profil « defaut » ne se supprime pas")
        if any(a["profil"] == nom for a in cfg["appareils"].values()):
            raise HTTPException(409, "profil utilisé par un appareil")
        del cfg["profils"][nom]
        valide = _enregistrer(cfg, ids)
    return {"version": valide["version"], "profils": valide["profils"]}


@app.get("/appareils", dependencies=[Depends(require_jwt)])
def lister_appareils():
    cfg = _config(_ids())
    connus = fichiers.lire_json(ETAT / "connus.json")
    connus = connus if isinstance(connus, dict) else {}
    res = fichiers.lire_json(ETAT / "resultat.json")
    exclus = res.get("exclus") if isinstance(res, dict) and isinstance(res.get("exclus"), dict) else {}
    carte = fichiers.lire_json(ETAT / "carte.json")
    adr_carte: dict = {}
    if isinstance(carte, dict) and isinstance(carte.get("adresses"), dict):
        for ip, i in carte["adresses"].items():
            if isinstance(i, dict) and isinstance(i.get("mac"), str):
                adr_carte.setdefault(i["mac"], []).append(ip)
    assignes = []
    for mac in sorted(cfg["appareils"]):
        a = cfg["appareils"][mac]
        adr = (connus.get(mac) or {}).get("adresses") or adr_carte.get(mac, [])
        assignes.append({"mac": mac, "nom": a["nom"], "profil": a["profil"], "exceptions": a["exceptions"], "adresses": adr, "exclu": exclus.get(mac)})
    autres = [{"mac": mac, "adresses": (v or {}).get("adresses", []), "vu": (v or {}).get("vu"), "exclu": exclus.get(mac)}
              for mac, v in sorted(connus.items()) if mac not in cfg["appareils"] and _MAC.match(mac)]
    return {"assignes": assignes, "connus": autres}


@app.post("/appareils/{mac}", dependencies=[Depends(require_jwt)])
def ecrire_appareil(mac: str, corps: AppareilIn):
    mac, ids = _mac(mac), _ids()
    with _VERROU_CONFIG:
        cfg = copy.deepcopy(_config(ids))
        cfg["appareils"][mac] = {"nom": corps.nom, "profil": corps.profil, "exceptions": corps.exceptions}
        valide = _enregistrer(cfg, ids)
    return {"version": valide["version"], "appareil": valide["appareils"][mac]}


@app.delete("/appareils/{mac}", dependencies=[Depends(require_jwt)])
def retirer_appareil(mac: str):
    mac, ids = _mac(mac), _ids()
    with _VERROU_CONFIG:
        cfg = copy.deepcopy(_config(ids))
        if mac not in cfg["appareils"]:
            raise HTTPException(404, "appareil inconnu")
        del cfg["appareils"][mac]
        valide = _enregistrer(cfg, ids)
    return {"version": valide["version"]}


def _taille_categorie(cat: str) -> int:
    n = 0
    for f in sorted((ETAT / "listes" / cat).glob("*.json")) if (ETAT / "listes" / cat).is_dir() else []:
        m = fichiers.lire_json(f)
        if isinstance(m, dict) and isinstance(m.get("n"), int) and not isinstance(m.get("n"), bool):
            n += m["n"]
    return n


def _estimation(cfg: dict) -> dict:
    """Zones, mémoire et durée de rechargement estimées (mesures du 2026-10-04) : UNE vue par configuration effective distincte."""
    vues = set()
    for mac in [""] + sorted(cfg["appareils"]):
        e = profils.effective(cfg, mac)
        vues.add((tuple(profils.bloquees(e)), tuple(sorted(e["autorise"]))))
    zones_n = sum(sum(_taille_categorie(c) for c in b) + len(a) for b, a in vues)
    return {"zones": zones_n, "memoire_mo": round(zones_n * 0.35 / 1024), "rechargement_s": round(6.9 + 2.5 * zones_n / 312000, 1)}


@app.get("/appliquer", dependencies=[Depends(require_jwt)])
def etat_application():
    cfg = _config(_ids())
    res = fichiers.lire_json(ETAT / "resultat.json")
    res = res if isinstance(res, dict) else None
    appliquee = res["version"] if res and res.get("statut") in ("applique", "inchange") and isinstance(res.get("version"), int) else 0
    return {"en_attente": cfg["version"] > appliquee, "version": cfg["version"], "appliquee": appliquee, "dernier": res, "estimation": _estimation(cfg)}


@app.post("/appliquer", status_code=202, dependencies=[Depends(require_jwt)])
def demander_application():
    """Dépose `appliquer.demande` ; l'unité root `secubox-webfilter-apply` applique (jamais dans ce processus, jamais par sudo)."""
    _ids()
    if not fichiers.deposer(ETAT, DEMANDE_APPLIQUER, DEMANDE_PERIMEE_S):
        raise HTTPException(409, "une application est déjà demandée ou en cours")
    return {"statut": "demandee"}
