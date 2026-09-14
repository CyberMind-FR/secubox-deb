# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: Voice — le CONTRAT DE MOTEUR (#1287).

POURQUOI UN CONTRAT ET NON UN MOTEUR. Le premier réflexe serait de choisir un
moteur vocal et de l'appeler directement. On s'interdit ce raccourci : le Hall ne
doit jamais savoir QUI produit le son. Il demande « dis ce texte avec cette voix »
et « transcris cet audio » ; ce module tranche l'implémentation.

LE CONTRAT EST CELUI D'OPENAI-AUDIO, ET CE N'EST PAS UN HOMMAGE. C'est la seule
interface audio que plusieurs moteurs indépendants servent déjà telle quelle, donc
la seule qui permette d'en changer sans réécrire le Hall :

    POST /v1/audio/speech          {model, input, voice, response_format} → octets
    POST /v1/audio/transcriptions  multipart(file, model)                 → {text}

DEUX IMPLÉMENTATIONS, INTERCHANGEABLES PAR CONFIGURATION :

  • `local`   — Piper (synthèse) et whisper.cpp (reconnaissance), tous deux arm64,
                invoqués en sous-processus. La box tient 1,8 Gio disponibles avec
                llama-server déjà résident : un modèle qui reste chargé la mettrait
                à genoux. Le sous-processus charge, produit, et rend la mémoire —
                on paie en latence ce qu'on refuse de payer en résidence.

  • `distant` — n'importe quel hôte servant le contrat ci-dessus, dont VoiceStudio
                (https://github.com/debpalash/VoiceStudio, port 3900) sur un poste
                x86. Il NE PEUT PAS tourner sur la box — ses binaires sont Linux
                x86_64/glibc≥2.39, il demande 8 Gio, et il est sous AGPL-3.0 avec
                des poids par défaut CC-BY-NC. À distance de bras, en revanche, il
                est parfaitement utilisable : processus séparé, appel réseau, aucun
                lien de code.

CE QU'ON NE FAIT JAMAIS. Si le moteur est injoignable, on le DIT. Pas de voix de
secours, pas de transcription approximative, pas de silence qui ressemble à un
succès : une panne de moteur doit se voir, comme la panne d'API des certificats.
"""
from __future__ import annotations

import asyncio
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

import httpx

from secubox_core.logger import get_logger

log = get_logger("voice")


class MoteurIndisponible(RuntimeError):
    """Le moteur ne peut pas répondre, et on refuse de faire semblant.

    Porte un message destiné à l'opérateur : il finira affiché tel quel dans la
    fenêtre de Lexie, donc il doit dire QUOI est en panne et OÙ regarder.
    """


@dataclass
class Etat:
    """Ce qu'on sait du moteur, sans rien supposer."""
    genre: str                 # « local » | « distant »
    joignable: bool
    detail: str                # phrase affichable telle quelle
    tts: bool = False          # la synthèse est-elle réellement disponible
    asr: bool = False          # la reconnaissance l'est-elle


class Moteur:
    """Interface commune. Les deux implémentations rendent exactement ceci."""

    async def etat(self) -> Etat:                                   # pragma: no cover
        raise NotImplementedError

    async def dire(self, texte: str, voix: str, format_: str) -> bytes:
        raise NotImplementedError                                   # pragma: no cover

    async def transcrire(self, audio: bytes, nom: str) -> str:
        raise NotImplementedError                                   # pragma: no cover


# ─────────────────────────────────────────────────────────────────────────────
# MOTEUR DISTANT — tout hôte parlant le contrat OpenAI-audio
# ─────────────────────────────────────────────────────────────────────────────

class MoteurDistant(Moteur):
    """Relaie vers un hôte servant /v1/audio/*.

    AUCUNE CLÉ N'EST OBLIGATOIRE : la cible visée est un moteur LOCAL au réseau
    de l'utilisateur, pas un service en nuage. Le champ existe parce que certains
    serveurs compatibles en exigent une, mais un déploiement souverain le laisse
    vide — et on ne journalise jamais sa valeur.
    """

    def __init__(self, url: str, modele_tts: str, modele_asr: str,
                 cle: str = "", delai_s: int = 60) -> None:
        self.url = url.rstrip("/")
        self.modele_tts = modele_tts
        self.modele_asr = modele_asr
        self._cle = cle
        self.delai_s = delai_s

    def _entetes(self) -> dict:
        return {"Authorization": f"Bearer {self._cle}"} if self._cle else {}

    async def etat(self) -> Etat:
        if not self.url:
            return Etat("distant", False,
                        "Aucun moteur distant configuré (voice.toml, [distant] url).")
        # On interroge la liste des voix : c'est la seule route du contrat qui
        # soit à la fois bon marché et révélatrice — si elle répond, le moteur
        # est là ET il sait au moins parler.
        try:
            async with httpx.AsyncClient(timeout=5) as cli:
                r = await cli.get(self.url + "/v1/audio/voices", headers=self._entetes())
        except (httpx.HTTPError, OSError) as e:
            return Etat("distant", False,
                        f"Moteur distant injoignable sur {self.url} — {type(e).__name__}.")
        if r.status_code >= 400:
            return Etat("distant", False,
                        f"Moteur distant à {self.url} : HTTP {r.status_code}.")
        return Etat("distant", True, f"Moteur distant à {self.url}.", tts=True, asr=True)

    async def dire(self, texte: str, voix: str, format_: str) -> bytes:
        if not self.url:
            raise MoteurIndisponible(
                "Aucun moteur distant configuré (voice.toml, [distant] url).")
        charge = {"model": self.modele_tts, "input": texte,
                  "voice": voix, "response_format": format_}
        try:
            async with httpx.AsyncClient(timeout=self.delai_s) as cli:
                r = await cli.post(self.url + "/v1/audio/speech",
                                   json=charge, headers=self._entetes())
        except (httpx.HTTPError, OSError) as e:
            raise MoteurIndisponible(
                f"Synthèse impossible : {self.url} injoignable ({type(e).__name__}).") from e
        if r.status_code >= 400:
            raise MoteurIndisponible(
                f"Synthèse refusée par le moteur distant : HTTP {r.status_code}.")
        return r.content

    async def transcrire(self, audio: bytes, nom: str) -> str:
        if not self.url:
            raise MoteurIndisponible(
                "Aucun moteur distant configuré (voice.toml, [distant] url).")
        fichiers = {"file": (nom, audio, "application/octet-stream")}
        try:
            async with httpx.AsyncClient(timeout=self.delai_s) as cli:
                r = await cli.post(self.url + "/v1/audio/transcriptions",
                                   data={"model": self.modele_asr},
                                   files=fichiers, headers=self._entetes())
        except (httpx.HTTPError, OSError) as e:
            raise MoteurIndisponible(
                f"Transcription impossible : {self.url} injoignable "
                f"({type(e).__name__}).") from e
        if r.status_code >= 400:
            raise MoteurIndisponible(
                f"Transcription refusée par le moteur distant : HTTP {r.status_code}.")
        try:
            return (r.json() or {}).get("text", "").strip()
        except ValueError as e:
            raise MoteurIndisponible(
                "Le moteur distant a répondu autre chose que du JSON.") from e


# ─────────────────────────────────────────────────────────────────────────────
# MOTEUR LOCAL — Piper + whisper.cpp, en sous-processus
# ─────────────────────────────────────────────────────────────────────────────

class MoteurLocal(Moteur):
    """Synthèse et reconnaissance sur la box, sans rien garder en mémoire.

    POURQUOI DES SOUS-PROCESSUS ET NON UN SERVEUR RÉSIDENT. Un serveur qui garde
    son modèle chargé répond plus vite — mais gk2 n'a pas cette mémoire à donner.
    Le sous-processus est le `lifecycle=on-demand` du monde des modèles : il
    coûte une latence de chargement par requête, et rend TOUT à la fin.
    """

    def __init__(self, piper: str, voix_dir: str, whisper: str,
                 modele_asr: str, delai_s: int = 120) -> None:
        self.piper = piper
        self.voix_dir = Path(voix_dir)
        self.whisper = whisper
        self.modele_asr = Path(modele_asr)
        self.delai_s = delai_s

    # — disponibilité ————————————————————————————————————————————————

    def _piper_ok(self) -> bool:
        return bool(shutil.which(self.piper)) and self.voix_dir.is_dir() \
            and any(self.voix_dir.glob("*.onnx"))

    def _whisper_ok(self) -> bool:
        return bool(shutil.which(self.whisper)) and self.modele_asr.is_file()

    async def etat(self) -> Etat:
        tts, asr = self._piper_ok(), self._whisper_ok()
        if tts and asr:
            detail = "Moteur local (Piper + whisper.cpp), modèles chargés à la demande."
        else:
            manque = []
            if not tts:
                manque.append(f"synthèse — {self.piper} ou une voix *.onnx dans {self.voix_dir}")
            if not asr:
                manque.append(f"reconnaissance — {self.whisper} ou le modèle {self.modele_asr}")
            detail = "Moteur local incomplet, il manque : " + " ; ".join(manque) + "."
        return Etat("local", tts or asr, detail, tts=tts, asr=asr)

    # — synthèse ——————————————————————————————————————————————————————

    def _voix_fichier(self, voix: str) -> Path:
        """Résout un nom de voix en fichier, SANS jamais sortir du répertoire.

        Le nom vient d'un manifeste, donc d'un paquet — mais un manifeste mal
        formé ne doit pas pouvoir faire lire `../../etc/shadow`. On ne garde que
        le nom de base, et on vérifie que le résultat est bien sous voix_dir.
        """
        base = Path(voix).name                       # neutralise tout chemin
        f = (self.voix_dir / f"{base}.onnx").resolve()
        racine = self.voix_dir.resolve()
        if racine not in f.parents or not f.is_file():
            raise MoteurIndisponible(
                f"Voix « {base} » introuvable dans {self.voix_dir}.")
        return f

    async def dire(self, texte: str, voix: str, format_: str) -> bytes:
        if not self._piper_ok():
            raise MoteurIndisponible((await self.etat()).detail)
        modele = self._voix_fichier(voix)
        # Piper écrit du WAV. On ne prétend pas produire autre chose : si
        # l'appelant demande de l'mp3, il doit le savoir, pas recevoir du WAV
        # étiqueté mp3.
        if format_ not in ("wav",):
            raise MoteurIndisponible(
                f"Le moteur local ne produit que du WAV, « {format_} » demandé.")
        def _run() -> bytes:
            with tempfile.NamedTemporaryFile(suffix=".wav") as sortie:
                p = subprocess.run(
                    [self.piper, "--model", str(modele), "--output_file", sortie.name],
                    input=texte.encode("utf-8"),
                    capture_output=True, timeout=self.delai_s)
                if p.returncode != 0:
                    raise MoteurIndisponible(
                        "Piper a échoué : " + p.stderr.decode("utf-8", "replace")[:200])
                return Path(sortie.name).read_bytes()
        try:
            return await asyncio.to_thread(_run)
        except subprocess.TimeoutExpired as e:
            raise MoteurIndisponible(
                f"Synthèse interrompue après {self.delai_s} s.") from e

    # — reconnaissance ————————————————————————————————————————————————

    async def transcrire(self, audio: bytes, nom: str) -> str:
        if not self._whisper_ok():
            raise MoteurIndisponible((await self.etat()).detail)
        def _run() -> str:
            with tempfile.TemporaryDirectory() as d:
                entree = Path(d) / "entree.wav"
                entree.write_bytes(audio)
                p = subprocess.run(
                    [self.whisper, "-m", str(self.modele_asr), "-f", str(entree),
                     "-l", "fr", "-nt", "-otxt", "-of", str(Path(d) / "sortie")],
                    capture_output=True, timeout=self.delai_s)
                if p.returncode != 0:
                    raise MoteurIndisponible(
                        "whisper.cpp a échoué : "
                        + p.stderr.decode("utf-8", "replace")[:200])
                txt = Path(d) / "sortie.txt"
                return txt.read_text(encoding="utf-8").strip() if txt.is_file() else ""
        try:
            return await asyncio.to_thread(_run)
        except subprocess.TimeoutExpired as e:
            raise MoteurIndisponible(
                f"Transcription interrompue après {self.delai_s} s.") from e


def construire(cfg: dict) -> Moteur:
    """Choisit l'implémentation d'après la configuration.

    Défaut = `local`. Un défaut `distant` enverrait l'audio du micro vers un hôte
    tiers dès l'installation, sans que personne l'ait demandé — sur une box dont
    tout l'argument est la souveraineté, ce serait le pire défaut possible.
    """
    genre = str(cfg.get("moteur", "local")).strip().lower()
    if genre == "distant":
        d = cfg.get("distant", {}) or {}
        return MoteurDistant(
            url=str(d.get("url", "")),
            modele_tts=str(d.get("modele_tts", "tts-1")),
            modele_asr=str(d.get("modele_asr", "whisper-1")),
            cle=str(d.get("cle", "")),
            delai_s=int(d.get("delai_s", 60)))
    l = cfg.get("local", {}) or {}
    return MoteurLocal(
        piper=str(l.get("piper", "piper")),
        voix_dir=str(l.get("voix_dir", "/usr/share/secubox/voice/voix")),
        whisper=str(l.get("whisper", "whisper-cli")),
        modele_asr=str(l.get("modele_asr",
                             "/usr/share/secubox/voice/modeles/ggml-base-q5_1.bin")),
        delai_s=int(l.get("delai_s", 120)))
