# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: Premier Pas — API des faces (#1522, couche 2)
CyberMind — https://cybermind.fr

Servie par l'agrégateur (utilisateur `secubox`, SANS privilège). Elle ne fait
que REMPLIR le profil (/var/lib/secubox/premier-pas/profil.toml) et DEMANDER
l'application : un fichier `demande` que surveille une unité .path root, qui
lance `premier-pasctl appliquer-demande`. Le moteur privilégié reste seul à
toucher le système.

QUI PEUT ÉCRIRE. Une box neuve n'a pas encore d'administrateur : on ne peut
pas exiger une session. Se fier à l'adresse ne suffit pas non plus — nginx
fait confiance à X-Forwarded-For venant du LAN, un voisin pourrait se faire
passer pour 127.0.0.1. D'où un JETON à usage de démarrage, créé par root dans
/run (0640 root:secubox), que le lanceur du kiosque passe à la page. Sans lui :
lecture seule. Une fois la box configurée (marqueur posé) : plus aucune
écriture, quelle que soit la preuve.

LE MOT DE PASSE ne fait que passer : haché en argon2 ici, seule l'empreinte
entre dans le profil (la règle du profil refuse le clair).
"""
from __future__ import annotations

import hmac
import os
import re
import sys
import tomllib
from pathlib import Path
from typing import Any, Dict, Optional

from fastapi import Depends, FastAPI, Header, HTTPException

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from premier_pas import moteur as M, profil as P  # noqa: E402

app = FastAPI(title="SecuBox Premier Pas", version="0.2.0")

DOSSIER = Path(os.environ.get("PREMIER_PAS_DIR", "/var/lib/secubox/premier-pas"))
JETON = Path(os.environ.get("PREMIER_PAS_JETON", "/run/secubox/premier-pas/jeton"))
MDP_MIN = 12


def _profil_path() -> Path:
    return DOSSIER / "profil.toml"


def _demande_path() -> Path:
    return DOSSIER / "demande"


def _marqueur() -> Path:
    return M.MARQUEUR


# ── Profil : lecture, écriture TOML minimale ───────────────────────────────

def _lit() -> Dict[str, Any]:
    try:
        return tomllib.loads(_profil_path().read_text())
    except (OSError, ValueError):
        return {}


def _toml_val(v: Any) -> str:
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, int):
        return str(v)
    s = str(v).replace("\\", "\\\\").replace('"', '\\"')
    return f'"{s}"'


def _ecrit(profil: Dict[str, Any]) -> None:
    lignes = ["# Profil Premier Pas — rempli par l'assistant (#1522)"]
    for section in ("box", "admin", "reseau", "services", "maillage", "apt"):
        bloc = profil.get(section)
        if not bloc:
            continue
        lignes += ["", f"[{section}]"] + [f"{k} = {_toml_val(v)}" for k, v in bloc.items() if v is not None]
    DOSSIER.mkdir(parents=True, exist_ok=True)
    tmp = _profil_path().with_suffix(".tmp")
    tmp.write_text("\n".join(lignes) + "\n")
    os.chmod(tmp, 0o640)
    os.replace(tmp, _profil_path())


# ── Garde ──────────────────────────────────────────────────────────────────

def ecriture(x_premier_pas: Optional[str] = Header(default=None)) -> None:
    if _marqueur().exists():
        raise HTTPException(409, "Cette box est déjà configurée : l'assistant est fermé.")
    try:
        attendu = JETON.read_text().strip()
    except OSError:
        raise HTTPException(503, "Assistant pas encore prêt : jeton de démarrage absent.")
    if not attendu or not x_premier_pas or not hmac.compare_digest(attendu, x_premier_pas.strip()):
        raise HTTPException(403, "L'assistant s'utilise depuis l'écran de la box.")


def _vue(profil: Dict[str, Any]) -> Dict[str, Any]:
    """Le profil sans l'empreinte du mot de passe."""
    v = {k: dict(b) for k, b in profil.items() if isinstance(b, dict)}
    if "admin" in v and "mot_de_passe" in v["admin"]:
        v["admin"]["mot_de_passe"] = "défini" if v["admin"]["mot_de_passe"] != "demander" else "demander"
    if "maillage" in v and v["maillage"].get("jeton"):
        v["maillage"]["jeton"] = "défini"
    return v


# ── Routes ─────────────────────────────────────────────────────────────────

@app.get("/etat")
def etat():
    profil = _lit()
    ex = P.examine(profil)
    try:
        import json
        moteur = json.loads(M.ETAT.read_text())
    except (OSError, ValueError):
        moteur = {}
    etapes = []
    for e in P.ETAPES:
        statut = "erreur" if e in ex.erreurs else ("a_faire" if e in ex.manquantes else "pret")
        etapes.append({"id": e, "libelle": P.LIBELLES[e], "statut": statut, "motif": ex.erreurs.get(e)})
    return {"fait": _marqueur().exists(), "complet": ex.complet, "reprendre": ex.premiere_etape,
            "etapes": etapes, "profil": _vue(profil), "moteur": moteur,
            "demande_en_cours": _demande_path().exists()}


@app.get("/choix")
def choix():
    """Ce que les étapes proposent : profils de services, fuseau et nom actuels."""
    try:
        fuseau = Path("/etc/timezone").read_text().strip()
    except OSError:
        fuseau = "Europe/Paris"
    try:
        nom = Path("/etc/hostname").read_text().strip()
    except OSError:
        nom = ""
    profils = []
    for p in sorted(P.PROFILS_DIR.glob("*.toml")) if P.PROFILS_DIR.is_dir() else []:
        try:
            d = tomllib.loads(p.read_text())
            profils.append({"id": p.stem, "libelle": d.get("label", p.stem), "modules": len(d.get("on", []))})
        except (OSError, ValueError):
            continue
    return {"fuseau": fuseau, "nom": nom, "profils": profils,
            "modes_reseau": list(P.MODES_RESEAU), "modes_maillage": list(P.MODES_MAILLAGE)}


_CHAMPS = {
    "bienvenue": ("box", {"langue", "clavier"}),
    "nom": ("box", {"nom"}),
    "horloge": ("box", {"fuseau", "ntp"}),
    "reseau": ("reseau", {"mode", "domaine"}),
    "services": ("services", {"profil"}),
    "maillage": ("maillage", {"mode", "rejoindre", "jeton"}),
    "majs": ("apt", {"auto", "heure"}),
}


@app.put("/etape/{etape}", dependencies=[Depends(ecriture)])
def enregistre(etape: str, valeurs: Dict[str, Any]):
    """Enregistre UNE étape ; rend l'examen à jour (l'erreur éventuelle est
    dite tout de suite, à l'étape où on la corrige)."""
    profil = _lit()
    if etape == "admin":
        mdp, conf = str(valeurs.get("mot_de_passe", "")), str(valeurs.get("confirmation", ""))
        if len(mdp) < MDP_MIN:
            raise HTTPException(400, f"Au moins {MDP_MIN} caractères.")
        if mdp != conf:
            raise HTTPException(400, "Les deux saisies diffèrent.")
        if mdp.lower() in {"secubox", "admin", "password", "motdepasse"} or re.fullmatch(r"(.)\1+", mdp):
            raise HTTPException(400, "Ce mot de passe est trop facile à deviner.")
        from argon2 import PasswordHasher  # noqa: PLC0415
        profil.setdefault("admin", {})["mot_de_passe"] = PasswordHasher().hash(mdp)
        profil["admin"]["totp"] = "enroler"
    elif etape in _CHAMPS:
        section, permis = _CHAMPS[etape]
        inconnus = set(valeurs) - permis
        if inconnus:
            raise HTTPException(400, f"Champs inconnus : {', '.join(sorted(inconnus))}")
        bloc = profil.setdefault(section, {})
        for k, v in valeurs.items():
            if isinstance(v, str):
                v = v.strip()
                if k in ("nom", "domaine"):
                    v = v.lower()
            bloc[k] = v
        if section == "reseau" and bloc.get("mode") == "lan":
            bloc.pop("domaine", None)
        if section == "maillage" and bloc.get("mode") != "rejoindre":
            bloc.pop("rejoindre", None)
            bloc.pop("jeton", None)
    else:
        raise HTTPException(404, "Étape inconnue.")
    _ecrit(profil)
    return etat()


@app.post("/appliquer", dependencies=[Depends(ecriture)])
def appliquer():
    ex = P.examine(_lit())
    if not ex.complet:
        raise HTTPException(409, f"Profil incomplet : reprendre à « {P.LIBELLES[ex.premiere_etape]} ».")
    DOSSIER.mkdir(parents=True, exist_ok=True)
    _demande_path().write_text("appliquer\n")
    return {"ok": True, "message": "Application demandée : la box se configure."}
