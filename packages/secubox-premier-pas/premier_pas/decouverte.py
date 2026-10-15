# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""
SecuBox-Deb :: Premier Pas — le maître REPÈRE les box neuves (#2728)

Demande du mainteneur : « gk2 repère les box neuves, les liste, puis pousse le profil en prenant la session distante au lieu du code ». Le code à 8×4 caractères affiché
sur l'écran de la box neuve (la preuve d'accès physique, #1522) devient facultatif : le maître prend la session distante de #2725 (fenêtre de 15 minutes après le démarrage de
la box, un seul poste, verdict LAN de nginx).

COMMENT ON REPÈRE. Les voisins du maître : la table ARP (`ip neigh`, IPv4 privées vues récemment) et les pairs du maillage (`wg show wg-mesh allowed-ips`, adresses /32). Chacun
reçoit UNE lecture publique, `GET /api/v1/premier-pas/etat` : une box SecuBox répond un JSON `{fait: bool, etapes: [...]}`. Rien d'autre n'est envoyé. `fait: false` = box neuve.
Jamais une adresse publique : `adresse_permise` (réseau local ou maillage seulement).

LE REGISTRE (`decouverte.json`, dans le dossier du maître) : adresse, nom annoncé, état (`nouvelle` → `preparee` → `configuree`), première et dernière vue, dernier envoi. Aucun secret : ni
mot de passe, ni empreinte, ni code, ni jeton de session. Une box qu'on ne voit plus depuis une heure disparaît.

CE QUI RESTE À LA MAIN DE L'ADMINISTRATEUR. Choisir le profil et le mode. L'envoi AUTOMATIQUE est désactivé par défaut ; activé, il est limité à `remplir` ou `proposer` (JAMAIS `forcer`),
à un profil COMPLET, et ne tente qu'UNE fois par box. Pourquoi : une machine du réseau qui répond « je suis neuve » à l'adresse d'un voisin n'est pas forcément la vôtre, et le profil porte
l'empreinte du mot de passe administrateur. `remplir` n'applique rien : la personne devant la box (ou le maître, d'un geste) décide ensuite.
"""
from __future__ import annotations

import ipaddress
import json
import logging
import os
import socket
import subprocess
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from . import maitre as MA
from . import profil as P
from . import remplir as R

journal = logging.getLogger("secubox.premier-pas")     # la trace va au journal systemd : audit.log est root 0644, l'API tourne en `secubox`
ABSENCE_S = 3600
MODES_AUTO = ("remplir", "proposer")
SONDE_DELAI_S = 3
TRAVAILLEURS = 16
ETATS_VUS = ("REACHABLE", "STALE", "DELAY", "PROBE", "PERMANENT")
DEFAUT = {"auto": False, "profil": "", "mode": "remplir"}


def _fichier() -> Path:
    return MA.dossier() / "decouverte.json"


def _lit() -> Dict[str, Any]:
    try:
        d = json.loads(_fichier().read_text())
    except (OSError, ValueError):
        d = {}
    if not isinstance(d, dict):
        d = {}
    if not isinstance(d.get("boxes"), dict):
        d["boxes"] = {}
    if not isinstance(d.get("reglages"), dict):
        d["reglages"] = {}
    return d


def _ecrit(d: Dict[str, Any]) -> None:
    dossier = MA.dossier()
    dossier.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=dossier, prefix=".decouverte-")
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(d, f, ensure_ascii=False)
        os.chmod(tmp, 0o640)
        os.replace(tmp, _fichier())
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def _ecrit_box(adresse: str, champs: Dict[str, Any]) -> None:
    d = _lit()
    d["boxes"].setdefault(adresse, {"adresse": adresse}).update(champs)
    _ecrit(d)


def liste() -> List[Dict[str, Any]]:
    boxes = [dict(b, adresse=a) for a, b in _lit()["boxes"].items() if isinstance(b, dict)]
    ordre = {"nouvelle": 0, "preparee": 1, "configuree": 2}
    return sorted(boxes, key=lambda b: (ordre.get(b.get("etat"), 3), -int(b.get("premiere_vue", 0)), b["adresse"]))


def oublie(adresse: str) -> None:
    d = _lit()
    d["boxes"].pop(MA.adresse_permise(adresse), None)
    _ecrit(d)


# ── réglages ──────────────────────────────────────────────────────────────

def reglages() -> Dict[str, Any]:
    return {**DEFAUT, **{k: v for k, v in _lit()["reglages"].items() if k in DEFAUT}}


def regle(r: Dict[str, Any]) -> Dict[str, Any]:
    auto, profil, mode = bool(r.get("auto")), str(r.get("profil") or ""), str(r.get("mode") or "remplir")
    if mode not in MODES_AUTO:
        raise R.Refus("Mode automatique : remplir ou proposer. « forcer » reste un geste de l'administrateur.")
    if auto:
        if not profil:
            raise R.Refus("Choisissez le profil à pousser automatiquement.")
        ex = P.examine(MA.lit(profil))
        if not ex.complet:
            raise R.Refus(f"Ce profil est incomplet : reprendre à « {P.LIBELLES[ex.premiere_etape]} ».")
    d = _lit()
    d["reglages"] = {"auto": auto, "profil": profil, "mode": mode}
    _ecrit(d)
    journal.warning("premier-pas maître : envoi automatique %s (profil « %s », mode %s)", "ACTIVÉ" if auto else "désactivé", profil, mode)
    return reglages()


# ── voisins ───────────────────────────────────────────────────────────────

def _lancer(cmd: List[str]) -> str:
    return subprocess.run(cmd, capture_output=True, text=True, timeout=5).stdout


def voisins(lancer: Optional[Callable[[List[str]], str]] = None, mes_adresses: Optional[List[str]] = None) -> List[str]:
    """Adresses privées vues récemment (ARP) et pairs du maillage (/32). Une commande absente ou illisible n'est pas une erreur."""
    lancer = lancer or _lancer
    mes = set(MA._mes_adresses() if mes_adresses is None else mes_adresses)
    vues: List[str] = []

    def retient(a: str) -> None:
        try:
            ip = ipaddress.ip_address(a)
        except ValueError:
            return
        if ip.version == 4 and ip.is_private and not ip.is_loopback and str(ip) not in mes and str(ip) not in vues:
            vues.append(str(ip))

    try:
        for e in json.loads(lancer(["ip", "-j", "-4", "neigh", "show"]) or "[]"):
            if any(s in ETATS_VUS for s in (e.get("state") or [])):
                retient(str(e.get("dst", "")))
    except (OSError, ValueError, subprocess.TimeoutExpired, AttributeError, TypeError):
        pass
    try:
        for ligne in (lancer(["wg", "show", "wg-mesh", "allowed-ips"]) or "").splitlines():
            for jeton in ligne.split("\t")[-1].split():
                if jeton.endswith("/32"):
                    retient(jeton[:-3])
    except (OSError, subprocess.TimeoutExpired):
        pass
    return vues


# ── sonde ─────────────────────────────────────────────────────────────────

def sonde(adresse: str, client=None) -> Optional[Dict[str, Any]]:
    try:
        adresse = MA.adresse_permise(adresse)
    except R.Refus:
        return None
    try:
        if client is None:
            import httpx  # noqa: PLC0415
            client = httpx.Client(verify=False, timeout=SONDE_DELAI_S)    # certificat auto-signé : réseau local ou maillage seulement
        r = client.get(f"https://{adresse}/api/v1/premier-pas/etat")
        if r.status_code != 200:
            return None
        d = r.json()
    except Exception:  # noqa: BLE001 — une machine qui ne répond pas, ou pas en JSON, n'est pas une box SecuBox
        return None
    if not isinstance(d, dict) or not isinstance(d.get("fait"), bool) or not isinstance(d.get("etapes"), list):
        return None
    nom = ((d.get("profil") or {}).get("box") or {}).get("nom") if isinstance(d.get("profil"), dict) else None
    return {"fait": d["fait"], "complet": bool(d.get("complet")), "nom": nom if isinstance(nom, str) else None}


# ── préparer ──────────────────────────────────────────────────────────────

def prepare(adresse: str, nom: str, mode: str = "remplir", client=None, maintenant: Callable[[], float] = time.time, auto: bool = False) -> Dict[str, Any]:
    """Pousse le profil `nom` à une box DÉTECTÉE et neuve, avec la session distante (pas de code)."""
    adresse = MA.adresse_permise(adresse)
    b = _lit()["boxes"].get(adresse)
    if not b:
        raise R.Refus("Cette box n'a pas été détectée : lancez d'abord l'analyse du réseau.")
    if b.get("etat") == "configuree":
        raise R.Refus("Cette box est déjà configurée : l'assistant est fermé.")
    try:
        res = MA.pousse(nom, adresse, "", mode, client=client, par=socket.gethostname())
    except R.Refus:
        raise
    except Exception as e:  # noqa: BLE001 — coupure réseau : on garde la trace, l'analyse continue
        res = {"ok": False, "faites": [], "arret": "Réseau", "detail": str(e)[:160]}
    ok = bool(res.get("ok"))
    journal.warning("premier-pas maître : %s %s vers %s, profil « %s », mode %s : %s", "envoi AUTOMATIQUE" if auto else "envoi", "réussi" if ok else "refusé", adresse, nom, mode,
                    "ok" if ok else f"{res.get('arret', '')} {res.get('detail', '')}"[:120])
    arret = None if ok else f"{res.get('arret', '')} : {res.get('detail', '')}".strip(" :")
    _ecrit_box(adresse, {"etat": "preparee" if ok else "nouvelle",
                         "dernier": {"le": int(maintenant()), "profil": nom, "mode": mode, "ok": ok, "auto": auto, "arret": arret}})
    return res


# ── analyser ──────────────────────────────────────────────────────────────

def analyse(client=None, voisins_fn: Optional[Callable[[], List[str]]] = None, maintenant: Callable[[], float] = time.time) -> Dict[str, Any]:
    now = int(maintenant())
    candidats = (voisins_fn or voisins)()
    if client is None and candidats:
        import httpx  # noqa: PLC0415
        client = httpx.Client(verify=False, timeout=SONDE_DELAI_S)
    with ThreadPoolExecutor(max_workers=max(1, min(TRAVAILLEURS, len(candidats)))) as pool:
        reponses = list(pool.map(lambda a: sonde(a, client), candidats))
    d = _lit()
    trouvees = 0
    for adresse, r in zip(candidats, reponses):
        if r is None:
            continue
        trouvees += 1
        b = d["boxes"].setdefault(adresse, {"adresse": adresse, "premiere_vue": now})
        b.setdefault("premiere_vue", now)
        b["derniere_vue"], b["nom"] = now, r["nom"]
        if r["fait"]:
            b["etat"] = "configuree"
        elif b.get("etat") in (None, "configuree"):
            b["etat"] = "nouvelle"
    for adresse in [a for a, b in d["boxes"].items() if now - int(b.get("derniere_vue", 0)) > ABSENCE_S]:
        del d["boxes"][adresse]
    _ecrit(d)
    rg = reglages()
    if rg["auto"] and rg["profil"]:
        for b in liste():
            if b.get("etat") == "nouvelle" and not b.get("dernier"):
                try:
                    prepare(b["adresse"], rg["profil"], rg["mode"], client=client, maintenant=lambda: now, auto=True)
                except R.Refus as e:
                    _ecrit_box(b["adresse"], {"dernier": {"le": now, "profil": rg["profil"], "mode": rg["mode"], "ok": False, "auto": True, "arret": str(e)}})
    return {"boxes": liste(), "sondees": len(candidats), "trouvees": trouvees}


# ── ligne de commande (minuterie du maître) ───────────────────────────────

def cli(sortie_json: bool = False, analyse_fn: Optional[Callable[[], Dict[str, Any]]] = None, imprime: Callable[[str], None] = print) -> int:
    """`premier-pasctl decouvrir` : une analyse du réseau, pour la minuterie du maître. Code 0 même sans rien trouver : ce n'est pas une panne."""
    r = (analyse_fn or analyse)()
    if sortie_json:
        imprime(json.dumps(r, ensure_ascii=False))
        return 0
    boxes = r.get("boxes", [])
    nouvelles = [b for b in boxes if b.get("etat") == "nouvelle"]
    imprime(f"{r.get('sondees', 0)} voisin(s) sondé(s), {r.get('trouvees', 0)} box SecuBox, {len(nouvelles)} nouvelle(s)")
    for b in boxes:
        imprime(f"  {b['adresse']:<16} {b.get('etat', '?'):<11} {b.get('nom') or '—'}")
    return 0
