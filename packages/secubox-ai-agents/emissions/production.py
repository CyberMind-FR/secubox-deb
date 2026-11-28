# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""File de production de l'atelier des émissions (#4058, Task 14).

Un brouillon = `<état>/brouillons/<id>/` ; `etat.json` dit où en est la chaîne de sept étapes, chacune écrit ses
fichiers dans le brouillon AVANT d'être marquée `faite` : une coupure (service tué, worker coupé) reprend à la première
étape non faite, sans relire gk2 ni réécrire le dialogue. Une production à la fois (`File`, FIFO, synthèse d'abord).
Aucune étape ne publie : la publication n'a lieu que par la route `/publier` (clic du propriétaire, Task 17).
"""
from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import os
import re
import secrets
import shutil
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Awaitable, Callable, Dict, List, Optional

from . import capture, consigne as consigne_mod, dialogue, evolutions as evolutions_mod, graphiques, montage, reglages

log = logging.getLogger("secubox-ai-emissions.production")

ETAPES = ("faits", "evolutions", "consigne", "dialogue", "verification", "voix", "montage")
FORMATS = ("synthese", "sujet")
ID_RE = re.compile(r"^e\d{14}-[0-9a-f]{6}$")
SOURCE_RE = re.compile(r"^(campagne|acteur)/[A-Za-z0-9_:.-]{1,80}$")
SOURCES_MAX = 12
_RANG_STATUT = {"verifiee": 0, "ia_seule": 1, "retiree": 2}


# ── outils injectés (les tests passent des faux) ────────────────────────────────────────────────────────────────
@dataclass
class Outils:
    sources: Any                                                         # emissions.sources.Sources
    magasin: Any                                                         # emissions.magasin.Magasin
    ecrire: Callable[[str], Awaitable[str]] = dialogue.ecrire
    dire: Optional[Callable[..., Awaitable[List[Path]]]] = None          # (brouillon, repliques, voix, voix_gpu)
    monter: Callable[..., Any] = montage.monter
    png: Callable[[str, Path], Path] = graphiques.png
    maintenant: Callable[[], float] = time.time
    reglages: Callable[[], Dict[str, Any]] = field(default=reglages.lire)


async def dire_reel(brouillon: Path, repliques: List[Dict[str, Any]], voix: Dict[int, str], voix_gpu: bool,
                    url: str = reglages.DEFAUTS["voix_url"]) -> List[Path]:
    from . import gpu
    from .voix import MoteurVoix, dire_tout
    return await dire_tout(brouillon, repliques, voix, moteur=MoteurVoix(url), verrou=gpu.selon_reglage(voix_gpu))


# ── brouillons ──────────────────────────────────────────────────────────────────────────────────────────────────
def dossier(base: Path, ident: str) -> Path:
    if not isinstance(ident, str) or not ID_RE.match(ident):
        raise ValueError("identifiant de brouillon invalide")
    return Path(base) / "brouillons" / ident


def _ecrire_json(f: Path, d: Any) -> None:
    f.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    tmp = f.with_name("." + f.name + ".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        json.dump(d, fh, ensure_ascii=False, indent=1)
    os.replace(tmp, f)


def _ecrire_texte(f: Path, t: str) -> None:
    fd = os.open(f.with_name("." + f.name + ".tmp"), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(t)
    os.replace(f.with_name("." + f.name + ".tmp"), f)


def lire_etat(base: Path, ident: str) -> Dict[str, Any]:
    return json.loads((dossier(base, ident) / "etat.json").read_text(encoding="utf-8"))


def ecrire_etat(base: Path, etat: Dict[str, Any]) -> None:
    etat["maj_le"] = int(time.time())
    _ecrire_json(dossier(base, etat["id"]) / "etat.json", etat)


def valider_sources(sources: Any) -> List[str]:
    if not isinstance(sources, list) or not 1 <= len(sources) <= SOURCES_MAX:
        raise ValueError(f"de 1 à {SOURCES_MAX} sources")
    if any(not isinstance(s, str) or not SOURCE_RE.match(s) or ".." in s for s in sources):
        raise ValueError("source invalide (campagne/<id> ou acteur/<id>)")
    return list(dict.fromkeys(sources))


def creer(base: Path, sources: List[str], format_: str, maintenant: float) -> Dict[str, Any]:
    if format_ not in FORMATS:
        raise ValueError("format : synthese ou sujet")
    sources = valider_sources(sources)
    stamp = datetime.fromtimestamp(maintenant or time.time(), timezone.utc).strftime("%Y%m%d%H%M%S")
    ident = f"e{stamp}-{secrets.token_hex(3)}"
    etat = {"id": ident, "format": format_, "sources": sources, "titre": "", "chapeau": "", "statut": "brouillon",
            "etape": 1, "etapes": [{"nom": n, "etat": "a_faire"} for n in ETAPES], "repliques": [], "diapos": {},
            "captures": {}, "chronologie": [], "images": [], "voix_fichiers": [], "erreur": None,
            "cree_le": int(maintenant or time.time())}
    ecrire_etat(base, etat)
    return etat


def lister(base: Path) -> List[Dict[str, Any]]:
    racine = Path(base) / "brouillons"
    out = []
    for d in sorted(racine.iterdir() if racine.is_dir() else [], reverse=True):
        if ID_RE.match(d.name):
            with contextlib.suppress(OSError, ValueError):
                e = lire_etat(base, d.name)
                out.append({k: e.get(k) for k in ("id", "format", "sources", "titre", "statut", "etape", "cree_le")})
    return out


def supprimer(base: Path, ident: str) -> None:
    shutil.rmtree(dossier(base, ident))


def resume_verification(repliques: List[Dict[str, Any]]) -> Dict[str, int]:
    out = {"verifiee": 0, "ia_seule": 0, "retiree": 0}
    for r in repliques:
        if r.get("statut") in out:
            out[r["statut"]] += 1
    return out


# ── étapes ──────────────────────────────────────────────────────────────────────────────────────────────────────
def _faits(d: Path) -> Dict[str, Dict[str, Any]]:
    return json.loads((d / "faits.json").read_text(encoding="utf-8"))


def _verifier_multi(repliques: List[Dict[str, Any]], dossiers: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Synthèse à plusieurs sujets : chaque réplique garde le MEILLEUR verdict obtenu contre l'un des dossiers
    (une réplique sur le sujet A n'est pas fausse parce que le dossier B l'ignore)."""
    meilleurs: List[Dict[str, Any]] = []
    for r in repliques:
        verdicts = [dialogue.verifier_repliques([r], d)[0] for d in dossiers] or [r]
        meilleurs.append(min(verdicts, key=lambda v: _RANG_STATUT.get(v.get("statut"), 3)))
    return meilleurs


def _diapos(repliques: List[Dict[str, Any]], graphs: List[Dict[str, Any]], captures: Dict[str, Any]) -> Dict[str, str]:
    """Rang → id de diapositive : graphiques associés, puis captures VALIDÉES posées sur une réplique."""
    d = {str(k): v for k, v in dialogue.associer_diapos(repliques, graphs).items()}
    for cid, c in (captures or {}).items():
        if isinstance(c, dict) and c.get("etat") == "validee" and isinstance(c.get("rang"), int):
            d[str(c["rang"])] = "capture:" + cid
    return d


def _titre(etat: Dict[str, Any], dossiers: List[Dict[str, Any]], maintenant: float) -> str:
    noms = [str((x.get("sujet") or {}).get("nom") or (x.get("sujet") or {}).get("id") or "?") for x in dossiers]
    if etat["format"] == "synthese":
        sem = datetime.fromtimestamp(maintenant, timezone.utc).isocalendar().week
        return f"La semaine du pare-feu — semaine {sem}"
    return f"Décryptage — {', '.join(noms)}"[:140]


async def _etape(nom: str, base: Path, etat: Dict[str, Any], o: Outils) -> None:
    d = dossier(base, etat["id"])
    r = o.reglages()
    if nom == "faits":
        faits = {}
        for s in etat["sources"]:
            genre, ident = s.split("/", 1)
            rep = await o.sources.dossier(genre, ident)
            faits[s] = rep.get("dossier") if isinstance(rep.get("dossier"), dict) else rep
        _ecrire_json(d / "faits.json", faits)
    elif nom == "evolutions":
        evo = {s: evolutions_mod.evolutions(x, o.magasin.dernier_valide(s), o.maintenant(),
                                            seuil_chiffre=float(r["ecart"]))
               for s, x in _faits(d).items()}
        _ecrire_json(d / "evolutions.json", evo)
        marquants = [f["texte"] for fs in evo.values() for f in fs if f.get("marquant")]
        etat["titre"] = etat.get("titre") or _titre(etat, list(_faits(d).values()), o.maintenant())
        etat["chapeau"] = etat.get("chapeau") or ("Ce qui a changé : " + " ".join(marquants[:3]))[:400]
    elif nom == "consigne":
        faits = _faits(d)
        evo = json.loads((d / "evolutions.json").read_text(encoding="utf-8"))
        texte = consigne_mod.consigne([x.get("sujet") or {} for x in faits.values()],
                                      [f for fs in evo.values() for f in fs], dialogue.GABARIT.read_text("utf-8"))
        _ecrire_texte(d / "consigne.txt", texte)
    elif nom == "dialogue":
        sortie = await o.ecrire((d / "consigne.txt").read_text(encoding="utf-8"))
        _ecrire_texte(d / "dialogue.txt", sortie)
        reps = dialogue.decouper(sortie)
        if not reps:
            raise RuntimeError("le moteur n'a rendu aucune réplique V1/V2")
        etat["repliques"] = reps
    elif nom == "verification":
        dossiers = list(_faits(d).values())
        etat["repliques"] = _verifier_multi(etat["repliques"], dossiers)
        graphs = []
        for k, x in enumerate(dossiers):
            for g in graphiques.graphiques(x):
                g = dict(g)
                g["id"] = g["id"] if len(dossiers) == 1 else f"s{k}-{g['id']}"
                graphs.append(g)
        _ecrire_json(d / "graphiques.json", graphs)
        etat["diapos"] = _diapos(etat["repliques"], graphs, capture._lire(d))
    elif nom == "voix":
        dites = dialogue.dites(etat["repliques"])
        if not dites:
            raise RuntimeError("aucune réplique à dire : toutes retirées")
        dire = o.dire or (lambda b, reps, v, g: dire_reel(b, reps, v, g, r["voix_url"]))
        fichiers = await dire(d, etat["repliques"], {1: r["voix1"], 2: r["voix2"]}, bool(r["voix_gpu"]))
        etat["voix_fichiers"] = [Path(f).name for f in fichiers]
    elif nom == "montage":
        graphs = {g["id"]: g for g in json.loads((d / "graphiques.json").read_text(encoding="utf-8"))}
        caps = capture._lire(d)
        diapos = _diapos(etat["repliques"], list(graphs.values()), caps)
        etat["diapos"] = diapos
        rangs = {int(k): v for k, v in diapos.items()}
        images = []
        (d / "diapos").mkdir(exist_ok=True, mode=0o700)
        for k, gid in enumerate(montage.ordre_images(etat["repliques"], rangs)):
            if gid.startswith("capture:"):
                images.append("captures/" + caps[gid.split(":", 1)[1]]["png"])
            else:
                nomf = f"{k:02d}-{gid}.png"
                await asyncio.to_thread(o.png, graphs[gid]["svg"], d / "diapos" / nomf)
                images.append("diapos/" + nomf)
        fichiers = [d / "voix" / n for n in etat["voix_fichiers"]]
        _, chrono = await asyncio.to_thread(o.monter, fichiers, etat["repliques"], rangs, d / "emission.mp3")
        etat["chronologie"], etat["images"] = chrono, images
        (d / "emission.mp4").unlink(missing_ok=True)                         # un MP4 ancien ne suit plus l'audio


async def produire(base: Path, ident: str, o: Outils) -> None:
    """Reprend à la première étape non `faite` ; une erreur marque l'étape `erreur` et remonte."""
    etat = lire_etat(base, ident)
    if etat.get("statut") == "publie":
        return
    etat.update(statut="en_cours", erreur=None)
    ecrire_etat(base, etat)
    for i, e in enumerate(etat["etapes"]):
        if e["etat"] == "faite":
            continue
        etat["etape"], e["etat"] = i + 1, "en_cours"
        ecrire_etat(base, etat)
        try:
            await _etape(e["nom"], base, etat, o)
        except BaseException as exc:
            e["etat"], etat["statut"] = "erreur", "erreur"
            etat["erreur"] = f"{e['nom']} : {type(exc).__name__} : {str(exc)[:300]}"
            ecrire_etat(base, etat)
            raise
        e["etat"] = "faite"
        ecrire_etat(base, etat)
    etat["statut"], etat["etape"] = "pret", len(ETAPES)
    ecrire_etat(base, etat)


def _rouvrir(etat: Dict[str, Any], depuis: str) -> None:
    """Remet à faire l'étape `depuis` et les suivantes (sans toucher aux précédentes)."""
    k = ETAPES.index(depuis)
    for e in etat["etapes"][k:]:
        e["etat"] = "a_faire"
    etat["etape"] = min(etat.get("etape", k + 1), k + 1)
    if etat.get("statut") in ("pret", "erreur"):
        etat["statut"] = "brouillon"


def modifier_replique(base: Path, ident: str, rang: int, texte: str) -> Dict[str, Any]:
    """Texte remplacé → revérifié contre les mêmes dossiers ; seules les étapes voix et montage sont rouvertes
    (la voix d'une réplique inchangée garde son fichier : un seul passage au worker)."""
    texte = " ".join(str(texte or "").split())
    if not texte or len(texte) > 2000:
        raise ValueError("texte vide ou trop long")
    etat = lire_etat(base, ident)
    if etat.get("statut") in ("en_cours", "publie"):
        raise RuntimeError("brouillon en production ou déjà publié")
    r = next((x for x in etat["repliques"] if x.get("rang") == rang), None)
    if r is None:
        raise KeyError(rang)
    r["texte"] = texte
    d = dossier(base, ident)
    faite = {e["nom"]: e["etat"] == "faite" for e in etat["etapes"]}
    if faite.get("verification"):
        v = _verifier_multi([r], list(_faits(d).values()))[0]
        r.update({k: v[k] for k in ("statut", "motifs", "marque")})
        graphs = json.loads((d / "graphiques.json").read_text(encoding="utf-8"))
        etat["diapos"] = _diapos(etat["repliques"], graphs, capture._lire(d))
        _rouvrir(etat, "voix")
    ecrire_etat(base, etat)
    return r


def rouvrir_montage(base: Path, ident: str) -> None:
    etat = lire_etat(base, ident)
    if {e["nom"]: e["etat"] for e in etat["etapes"]}.get("voix") == "faite":
        _rouvrir(etat, "montage")
        ecrire_etat(base, etat)


async def reecrire(base: Path, ident: str, rang: int, o: Outils) -> Dict[str, Any]:
    """PROPOSITION de réécriture d'une réplique (✗ ou ⚠) par le LLM, vérifiée, jamais appliquée d'office : le
    propriétaire l'accepte par `modifier_replique`."""
    etat = lire_etat(base, ident)
    r = next((x for x in etat["repliques"] if x.get("rang") == rang), None)
    if r is None:
        raise KeyError(rang)
    d = dossier(base, ident)
    base_consigne = (d / "consigne.txt").read_text(encoding="utf-8")
    motifs = "; ".join(str(m) for m in r.get("motifs") or []) or "aucun"
    demande = "\n\n".join([
        base_consigne,
        f"Réécris UNE réplique de ce dialogue. La voici (voix {r['voix']}) : « {r['texte']} »",
        f"Elle a été refusée ou signalée par le contrôle pour : {motifs}.",
        "N'utilise QUE les chiffres et faits donnés plus haut ; si un chiffre n'y figure pas, ne le cite pas. "
        f"Rends une seule ligne, commençant par « V{r['voix']}: »."])
    sortie = await o.ecrire(demande)
    props = dialogue.decouper(sortie)
    if not props:
        raise RuntimeError("le moteur n'a rendu aucune réplique")
    p = {"rang": rang, "voix": r["voix"], "texte": props[0]["texte"]}
    return _verifier_multi([p], list(_faits(d).values()))[0]


# ── file : une production à la fois ─────────────────────────────────────────────────────────────────────────────
class File:
    """FIFO, une seule production à la fois (`asyncio.Lock`), la synthèse passe devant les émissions par sujet.
    Travaux : `produire` (chaîne) ou `mp4` (vidéo à la demande)."""

    def __init__(self, base: Path, outils: Outils) -> None:
        self.base, self.outils = Path(base), outils
        self._attente: List[tuple] = []
        self._signal = asyncio.Event()
        self._verrou = asyncio.Lock()
        self._tache: Optional[asyncio.Task] = None
        self.en_cours: Optional[str] = None

    def attente(self) -> List[str]:
        return [i for i, _ in self._attente]

    async def mettre(self, ident: str, travail: str = "produire") -> None:
        etat = lire_etat(self.base, ident)
        if any(i == ident and t == travail for i, t in self._attente) or (self.en_cours == ident):
            return
        if travail == "produire":
            etat["statut"] = "en_file"
            ecrire_etat(self.base, etat)
        entree = (ident, travail)
        if etat.get("format") == "synthese":
            k = next((n for n, (i, _) in enumerate(self._attente)
                      if lire_etat(self.base, i).get("format") != "synthese"), len(self._attente))
            self._attente.insert(k, entree)
        else:
            self._attente.append(entree)
        self._signal.set()

    async def _un(self, ident: str, travail: str) -> None:
        async with self._verrou:
            self.en_cours = ident
            try:
                if travail == "mp4":
                    await faire_mp4(self.base, ident)
                else:
                    await produire(self.base, ident, self.outils)
            except asyncio.CancelledError:
                raise
            except Exception as e:  # noqa: BLE001 — journalisé et visible dans etat.json ; la file continue
                log.error("production %s : %s", ident, e)
            finally:
                self.en_cours = None

    async def _boucle(self) -> None:
        while True:
            while not self._attente:
                self._signal.clear()
                await self._signal.wait()
            ident, travail = self._attente.pop(0)
            with contextlib.suppress(FileNotFoundError, ValueError):
                await self._un(ident, travail)

    def demarrer(self) -> None:
        if self._tache is None:
            self._tache = asyncio.create_task(self._boucle())

    async def vider(self) -> None:
        while self._attente or self.en_cours:
            await asyncio.sleep(0.01)

    async def arreter(self) -> None:
        if self._tache:
            self._tache.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._tache
            self._tache = None

    async def reprendre_au_demarrage(self) -> int:
        """Brouillons laissés `en_file` / `en_cours` par un arrêt du service : remis en file."""
        n = 0
        for b in lister(self.base):
            if b["statut"] in ("en_file", "en_cours"):
                await self.mettre(b["id"])
                n += 1
        return n


async def faire_mp4(base: Path, ident: str) -> Path:
    """MP4 SUR DEMANDE seulement (route `/mp4`) : jamais produit par la chaîne."""
    etat = lire_etat(base, ident)
    if etat.get("statut") != "pret" or not etat.get("chronologie"):
        raise RuntimeError("montage non fait : pas de MP4")
    d = dossier(base, ident)
    return await asyncio.to_thread(montage.video, d / "emission.mp3", etat["chronologie"],
                                   [d / i for i in etat["images"]], d / "emission.mp4")
