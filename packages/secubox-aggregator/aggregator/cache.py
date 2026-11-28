# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""
SecuBox-Deb :: secubox-aggregator — précache des lectures en double tampon (#4037)
CyberMind — https://cybermind.fr

Intermédiaire ASGI « stale-while-revalidate » pour les GET `/api/v1/<module>/…` :
chaque webui reçoit tout de suite le DERNIER CALCUL COMPLET, puis le recalcul
se fait derrière.

États d'une entrée (âge = maintenant − fin du calcul) :
  * âge < ttl                → `frais`  : servie telle quelle ;
  * ttl ≤ âge < perime_max   → `perime` : servie AUSSITÔT, recalcul en arrière-plan
                               (un seul par clé, nombre total plafonné) ;
  * âge ≥ perime_max, ou entrée invalidée par une écriture du module
                             → recalcul lancé, attendu `delai_synchrone` s ;
                               au-delà, la vieille réponse est servie (`perime`)
                               et le recalcul continue pour la suivante ;
  * absente                  → calcul normal (réponse relayée telle quelle,
                               en flux), copiée si elle est gardable (`absent`).
  * âge ≥ conservation       → entrée oubliée.

Double tampon : seule une réponse 200 `application/json`, sans `Set-Cookie` ni
`Cache-Control: no-store`, de taille bornée, remplace l'entrée. Une erreur, un
5xx, un 401/403, une expiration ne l'écrasent jamais (401/403 la retirent : le
porteur n'y a plus droit).

ISOLATION : la clé est `GET` + chemin + requête + condensat SHA-256 de tout ce
qui peut changer la réponse d'une garde : `Authorization`, `Cookie` (en entier),
`Host`, `X-Real-IP`, `X-Forwarded-For`, `Accept-Language`. Deux porteurs
différents n'ont jamais la même clé ; un même jeton depuis une autre adresse
(zones LAN/maillage de `require_lecture`) non plus. Le recalcul d'arrière-plan
rejoue la requête avec SES en-têtes : la garde du module est réévaluée à chaque
recalcul. Les en-têtes rejoués restent dans la mémoire du processus, jamais
sur disque. Un jeton révoqué peut encore lire, au plus `perime_max` s plus une
passe, la réponse qu'il avait obtenue ; son premier recalcul refusé la retire.

Aucun verrou : tout l'état vit sur la boucle unique de l'agrégateur. Chaque
recalcul est borné (`delai_recalcul`), suivi, annulé à l'arrêt.
"""
from __future__ import annotations

import asyncio
import hashlib
import logging
import time
from collections import OrderedDict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple

log = logging.getLogger("secubox.aggregator.cache")

PREFIXE = "/api/v1/"
ENTETE = "x-sbx-cache"
INSTANCE: Optional["CacheLecture"] = None

# En-têtes qui entrent dans le condensat d'identité (voir l'en-tête du module).
_ENTETES_IDENTITE = (b"authorization", b"cookie", b"host", b"x-real-ip", b"x-forwarded-for",
                     b"accept-language")
# En-têtes de réponse jamais recopiés depuis l'entrée gardée.
_ENTETES_NON_GARDES = frozenset({b"content-length", b"date", b"server", b"set-cookie", b"transfer-encoding",
                                 b"connection", b"age", ENTETE.encode(), b"x-sbx-cache-age",
                                 b"x-sbx-cache-date"})

# Modules jamais mis en cache : connexion et coffre (secrets, jetons à usage
# unique), canal du pilotage (jamais relayé).
MODULES_EXCLUS_DEFAUT = frozenset({"auth", "vault", "pilotage-canal", "pilotage"})

# Segments de chemin jamais mis en cache : flux, téléchargements, exports,
# santé, jetons, journaux suivis.
SEGMENTS_EXCLUS_DEFAUT = frozenset({
    "health", "healthz", "stream", "events", "sse", "ws", "websocket", "live", "tail", "follow",
    "flux", "download", "telecharger", "export", "exporter", "backup", "sauvegarde", "archive",
    "login", "logout", "session", "token", "jeton", "csrf", "nonce", "otp", "totp", "qr", "qrcode",
    "me", "whoami", "moi", "pair", "invite", "invitation", "wake", "reveil", "ping",
    # GET à effet de bord (relance, balayage, sonde) : jamais servis depuis le cache.
    "refresh", "rafraichir", "reload", "scan", "probe", "sonde", "test",
})

# TTL par dernier segment du chemin (contenu) ; défaut `ttl_defaut`.
TTL_SEGMENT_DEFAUT: Dict[str, float] = {
    "status": 5.0, "etat": 5.0, "state": 5.0,
    "stats": 30.0, "metrics": 30.0, "mesures": 30.0, "summary": 30.0, "resume": 30.0,
    "rapports": 60.0, "reports": 60.0, "categories": 60.0, "history": 60.0, "historique": 60.0,
    "config": 60.0, "settings": 60.0, "reglages": 60.0, "info": 120.0, "version": 300.0,
}


@dataclass
class Reglages:
    actif: bool = True
    ttl_defaut: float = 15.0
    perime_max: float = 600.0
    conservation: float = 3600.0
    delai_synchrone: float = 3.0
    delai_recalcul: float = 90.0
    recalculs_max: int = 8
    entrees_max: int = 2000
    octets_max: int = 64 * 1024 * 1024
    entree_octets_max: int = 2 * 1024 * 1024
    ttl: Dict[str, float] = field(default_factory=dict)        # "module" ou "module/chemin" → s (0 = exclu)
    exclus: List[str] = field(default_factory=list)            # "module" ou "module/chemin" (préfixe)

    @classmethod
    def depuis_toml(cls, section: Optional[dict]) -> "Reglages":
        r = cls()
        if not isinstance(section, dict):
            return r
        for nom in ("ttl_defaut", "perime_max", "conservation", "delai_synchrone", "delai_recalcul"):
            v = section.get(nom)
            if isinstance(v, (int, float)) and not isinstance(v, bool) and v >= 0:
                setattr(r, nom, float(v))
        for nom in ("recalculs_max", "entrees_max", "octets_max", "entree_octets_max"):
            v = section.get(nom)
            if isinstance(v, int) and not isinstance(v, bool) and v > 0:
                setattr(r, nom, v)
        if isinstance(section.get("actif"), bool):
            r.actif = section["actif"]
        ttl = section.get("ttl")
        if isinstance(ttl, dict):
            r.ttl = {str(k).strip("/"): float(v) for k, v in ttl.items()
                     if isinstance(v, (int, float)) and not isinstance(v, bool) and v >= 0}
        exclus = section.get("exclus")
        if isinstance(exclus, list):
            r.exclus = [str(x).strip("/") for x in exclus if isinstance(x, str) and x.strip("/")]
        return r


@dataclass
class _Entree:
    statut: int
    entetes: List[Tuple[bytes, bytes]]
    corps: bytes
    fin: float            # time.monotonic() à la fin du calcul
    date: str             # RFC 3339 UTC de la fin du calcul
    module: str
    invalide: bool = False


def _maintenant_rfc3339() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class _Capture:
    """Reçoit les messages d'envoi d'une réponse et la garde si elle est gardable."""

    def __init__(self, plafond: int):
        self.plafond = plafond
        self.statut = 0
        self.entetes: List[Tuple[bytes, bytes]] = []
        self.morceaux: List[bytes] = []
        self.taille = 0
        self.gardable = False
        self.complete = False

    def debut(self, message: dict) -> None:
        self.statut = int(message.get("status", 0))
        self.entetes = [(bytes(k).lower(), bytes(v)) for k, v in message.get("headers", [])]
        noms = {k: v for k, v in self.entetes}
        type_ = noms.get(b"content-type", b"").split(b";")[0].strip().lower()
        cc = noms.get(b"cache-control", b"").lower()
        self.gardable = (self.statut == 200 and type_ == b"application/json" and b"set-cookie" not in noms
                         and b"no-store" not in cc and b"private" not in cc)

    def corps(self, message: dict) -> None:
        if not self.gardable:
            return
        morceau = message.get("body", b"") or b""
        self.taille += len(morceau)
        if self.taille > self.plafond:
            self.gardable = False
            self.morceaux = []
            return
        self.morceaux.append(morceau)
        if not message.get("more_body", False):
            self.complete = True


class CacheLecture:
    """Intermédiaire ASGI. `app` = application interne (routage de l'agrégateur)."""

    def __init__(self, app, reglages: Optional[Reglages] = None):
        global INSTANCE
        self.app = app
        self.r = reglages or Reglages()
        self._entrees: "OrderedDict[str, _Entree]" = OrderedDict()
        self._octets = 0
        self._en_cours: Dict[str, asyncio.Task] = {}
        self._generation: Dict[str, int] = {}
        self.compteurs: Dict[str, int] = {"frais": 0, "perime": 0, "absent": 0, "contourne": 0,
                                          "recalculs": 0, "recalculs_refuses": 0, "invalidations": 0}
        INSTANCE = self  # /health et l'arrêt de l'agrégateur y accèdent (pile construite par Starlette)

    # ── Politique ────────────────────────────────────────────────────────────
    @staticmethod
    def _decouper(chemin: str) -> Tuple[str, str]:
        reste = chemin[len(PREFIXE):]
        module, _, sous = reste.partition("/")
        return module, sous.strip("/")

    def ttl_pour(self, module: str, sous: str) -> float:
        """TTL en s ; 0 = jamais mis en cache."""
        if module in MODULES_EXCLUS_DEFAUT:
            return 0.0
        complet = f"{module}/{sous}".strip("/")
        for ex in self.r.exclus:
            if complet == ex or complet.startswith(ex + "/"):
                return 0.0
        # Surcharge TOML : le préfixe le plus long gagne (« waf/categories » avant « waf »).
        meilleur = None
        for cle, val in self.r.ttl.items():
            if complet == cle or complet.startswith(cle + "/"):
                if meilleur is None or len(cle) > len(meilleur[0]):
                    meilleur = (cle, val)
        segments = [s.lower() for s in sous.split("/") if s]
        if meilleur is not None:
            return meilleur[1]
        if any(s in SEGMENTS_EXCLUS_DEFAUT for s in segments):
            return 0.0
        if segments and segments[-1] in TTL_SEGMENT_DEFAUT:
            return TTL_SEGMENT_DEFAUT[segments[-1]]
        return self.r.ttl_defaut

    @staticmethod
    def cle(scope: dict) -> str:
        h = hashlib.sha256()
        for nom in _ENTETES_IDENTITE:
            for k, v in scope.get("headers") or []:
                if bytes(k).lower() == nom:
                    h.update(nom + b"=" + bytes(v) + b"\0")
        qs = scope.get("query_string", b"") or b""
        return f"GET {scope.get('path', '')}?{qs.decode('latin-1')} {h.hexdigest()}"

    # ── Mémoire bornée (LRU) ─────────────────────────────────────────────────
    def _poids(self, e: _Entree) -> int:
        return len(e.corps) + sum(len(k) + len(v) for k, v in e.entetes) + 256

    def _retirer(self, cle: str) -> None:
        e = self._entrees.pop(cle, None)
        if e is not None:
            self._octets -= self._poids(e)

    def _ranger(self, cle: str, e: _Entree) -> None:
        self._retirer(cle)
        self._entrees[cle] = e
        self._octets += self._poids(e)
        while self._entrees and (len(self._entrees) > self.r.entrees_max or self._octets > self.r.octets_max):
            vieille, _ = next(iter(self._entrees.items()))
            self._retirer(vieille)

    def _lire(self, cle: str) -> Optional[_Entree]:
        e = self._entrees.get(cle)
        if e is None:
            return None
        if time.monotonic() - e.fin >= self.r.conservation:
            self._retirer(cle)
            return None
        self._entrees.move_to_end(cle)
        return e

    def invalider_module(self, module: str) -> None:
        """Une écriture sur le module : ses entrées deviennent invalides (servies seulement en repli, après
        `delai_synchrone`), et un recalcul lancé avant l'écriture ne range plus son résultat."""
        self._generation[module] = self._generation.get(module, 0) + 1
        for e in self._entrees.values():
            if e.module == module:
                e.invalide = True
        self.compteurs["invalidations"] += 1

    def etat(self) -> dict:
        return {"actif": self.r.actif, "entrees": len(self._entrees), "octets": self._octets,
                "recalculs_en_cours": len(self._en_cours), **self.compteurs}

    async def fermer(self) -> None:
        taches = list(self._en_cours.values())
        for t in taches:
            t.cancel()
        if taches:
            await asyncio.gather(*taches, return_exceptions=True)
        self._en_cours.clear()

    # ── Recalcul ─────────────────────────────────────────────────────────────
    async def _calculer(self, cle: str, scope: dict, module: str, generation: int) -> Optional[_Entree]:
        """Rejoue la requête (sans client) et range le résultat s'il est gardable. `generation` est relevée au
        LANCEMENT (la tâche ne démarre qu'au prochain passage de la boucle, peut-être après une écriture)."""
        capture = _Capture(self.r.entree_octets_max)
        fini = asyncio.Event()
        corps_envoye = False

        async def recevoir() -> dict:
            nonlocal corps_envoye
            if not corps_envoye:
                corps_envoye = True
                return {"type": "http.request", "body": b"", "more_body": False}
            await fini.wait()
            return {"type": "http.disconnect"}

        async def envoyer(message: dict) -> None:
            if message["type"] == "http.response.start":
                capture.debut(message)
            elif message["type"] == "http.response.body":
                capture.corps(message)
                if not message.get("more_body", False) or not capture.gardable:
                    fini.set()

        self.compteurs["recalculs"] += 1
        try:
            await asyncio.wait_for(self._appeler(scope, recevoir, envoyer, fini), timeout=self.r.delai_recalcul)
        except asyncio.TimeoutError:
            log.warning("[cache] recalcul de %s trop long (> %s s) : entrée gardée", scope.get("path"),
                        self.r.delai_recalcul)
            return None
        except Exception:  # noqa: BLE001 — le module a levé : l'entrée gardée reste, l'erreur est journalisée
            log.exception("[cache] recalcul de %s en échec : entrée gardée", scope.get("path"))
            return None
        finally:
            fini.set()
        if capture.statut in (401, 403):
            self._retirer(cle)
            return None
        if not (capture.gardable and capture.complete):
            return None
        if self._generation.get(module, 0) != generation:
            return None  # une écriture est passée pendant le calcul : résultat d'avant l'écriture
        e = _Entree(capture.statut, [(k, v) for k, v in capture.entetes if k not in _ENTETES_NON_GARDES],
                    b"".join(capture.morceaux), time.monotonic(), _maintenant_rfc3339(), module)
        self._ranger(cle, e)
        return e

    async def _appeler(self, scope, recevoir, envoyer, fini: asyncio.Event) -> None:
        """L'application peut finir avant ou après le dernier morceau ; on s'arrête au premier des deux."""
        tache = asyncio.ensure_future(self.app(scope, recevoir, envoyer))
        attente = asyncio.ensure_future(fini.wait())
        try:
            await asyncio.wait({tache, attente}, return_when=asyncio.FIRST_COMPLETED)
            if tache.done():
                tache.result()
        finally:
            for t in (tache, attente):
                if not t.done():
                    t.cancel()
            await asyncio.gather(tache, attente, return_exceptions=True)

    def _lancer(self, cle: str, scope: dict, module: str) -> Optional[asyncio.Task]:
        """Un seul recalcul par clé ; au plus `recalculs_max` en tout (sinon on sert ce qu'on a)."""
        tache = self._en_cours.get(cle)
        if tache is not None and not tache.done():
            return tache
        if len(self._en_cours) >= self.r.recalculs_max:
            self.compteurs["recalculs_refuses"] += 1
            return None
        tache = asyncio.ensure_future(self._calculer(cle, scope, module, self._generation.get(module, 0)))
        self._en_cours[cle] = tache

        def _fin(t: asyncio.Task, cle=cle) -> None:
            if self._en_cours.get(cle) is t:
                del self._en_cours[cle]
            if not t.cancelled() and t.exception() is not None:
                log.error("[cache] recalcul %s : %s", cle.split(" ")[1], t.exception())

        tache.add_done_callback(_fin)
        return tache

    # ── Service ──────────────────────────────────────────────────────────────
    async def _servir(self, send, e: _Entree, etat: str) -> None:
        age = max(0, int(time.monotonic() - e.fin))
        entetes = list(e.entetes) + [
            (b"content-length", str(len(e.corps)).encode()),
            (ENTETE.encode(), f"{etat}; age={age}".encode()),
            (b"x-sbx-cache-age", str(age).encode()),
            (b"x-sbx-cache-date", e.date.encode()),
            (b"age", str(age).encode()),
        ]
        self.compteurs[etat] += 1
        await send({"type": "http.response.start", "status": e.statut, "headers": entetes})
        await send({"type": "http.response.body", "body": e.corps, "more_body": False})

    async def _absent(self, cle: str, scope: dict, receive, send, module: str) -> None:
        """Calcul au premier plan, relayé en flux ; copie gardée si la réponse l'est."""
        generation = self._generation.get(module, 0)
        capture = _Capture(self.r.entree_octets_max)

        async def envoyer(message: dict) -> None:
            if message["type"] == "http.response.start":
                capture.debut(message)
                message = dict(message)
                message["headers"] = list(message.get("headers", [])) + [(ENTETE.encode(), b"absent; age=0")]
            elif message["type"] == "http.response.body":
                capture.corps(message)
            await send(message)

        self.compteurs["absent"] += 1
        await self.app(scope, receive, envoyer)
        if capture.gardable and capture.complete and self._generation.get(module, 0) == generation:
            self._ranger(cle, _Entree(capture.statut,
                                      [(k, v) for k, v in capture.entetes if k not in _ENTETES_NON_GARDES],
                                      b"".join(capture.morceaux), time.monotonic(), _maintenant_rfc3339(), module))

    async def __call__(self, scope, receive, send):
        if scope.get("type") == "lifespan" or not self.r.actif or scope.get("type") != "http":
            await self.app(scope, receive, send)
            return
        chemin = scope.get("path", "") or ""
        methode = scope.get("method", "GET")
        if not chemin.startswith(PREFIXE):
            await self.app(scope, receive, send)
            return
        module, sous = self._decouper(chemin)
        if methode in ("POST", "PUT", "PATCH", "DELETE"):
            # Avant ET après l'écriture : rien de ce qui a été calculé avant elle n'est rangé ni servi frais.
            self.invalider_module(module)
            try:
                await self.app(scope, receive, send)
            finally:
                self.invalider_module(module)
            return
        if methode != "GET" or not module:
            await self.app(scope, receive, send)
            return
        ttl = self.ttl_pour(module, sous)
        contourne = any(bytes(k).lower() == ENTETE.encode() and bytes(v).strip().lower() == b"contourner"
                        for k, v in scope.get("headers") or [])
        if ttl <= 0 or contourne:
            if contourne:
                self.compteurs["contourne"] += 1
            await self.app(scope, receive, send)
            return
        cle = self.cle(scope)
        e = self._lire(cle)
        if e is None:
            await self._absent(cle, scope, receive, send, module)
            return
        age = time.monotonic() - e.fin
        if not e.invalide and age < ttl:
            await self._servir(send, e, "frais")
            return
        rejeu = _copier_scope(scope)
        if not e.invalide and age < self.r.perime_max:
            self._lancer(cle, rejeu, module)
            await self._servir(send, e, "perime")
            return
        # Trop vieille ou invalidée : on attend le recalcul un temps borné, sinon la vieille.
        tache = self._lancer(cle, rejeu, module)
        if tache is not None:
            done, _ = await asyncio.wait({tache}, timeout=self.r.delai_synchrone)
            if done and not tache.cancelled() and tache.exception() is None and tache.result() is not None:
                await self._servir(send, tache.result(), "frais")
                return
        if cle not in self._entrees:
            # Retirée entre-temps (401/403 au recalcul) : la garde décide, au premier plan.
            await self._absent(cle, scope, receive, send, module)
            return
        await self._servir(send, e, "perime")


def _copier_scope(scope: dict) -> dict:
    """Instantané de la portée AVANT le routage (Starlette la modifie en place : route, root_path, path_params)."""
    copie = {k: v for k, v in scope.items() if k not in ("endpoint", "route", "path_params", "router")}
    copie["headers"] = list(scope.get("headers") or [])
    if isinstance(scope.get("state"), dict):
        copie["state"] = dict(scope["state"])
    return copie

