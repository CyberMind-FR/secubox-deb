# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""Comptes de service par clé Ed25519 (#3716) : `ai-ban`, l'IA qui bannit sur gk2.

CE N'EST PAS UN COMPTE DE SECUBOX-AUTH, NI UNE SESSION. Sur le modèle du porteur délégué du pilotage (#3126 L5) :

- la clé PRIVÉE Ed25519 reste sur la box de l'IA ; gk2 ne garde que la clé PUBLIQUE, dans un arbre root
  (`DOSSIER_COMPTES_SERVICE/<compte>/<kid>.pub`, dossiers et fichiers à root, sans écriture pour le groupe ni les
  autres, lus sans suivre de lien par `auth._lire_fichier_root`). gk2 ne détient donc aucun secret capable de
  frapper un jeton de compte de service — à la différence d'une session HS256, dont `jwt_secret` est lu par tous les
  modules ;
- un jeton PAR REQUÊTE : en-tête `alg = EdDSA`, `kid` = SHA-256 hex du DER SubjectPublicKeyInfo de la clé publique ;
  réclamations `sub` = le compte, `aud` = `auth.nom_box_locale()`, `portee` = `COMPTES_SERVICE[compte]`, `iat`,
  `exp` (`exp - iat ≤ DUREE_MAX_S`, dérive `DERIVE_S`), `jti` (32 hex, USAGE UNIQUE), `corps` = SHA-256 hex du corps
  brut (`b""` pour un GET) : un jeton capturé ne vaut que pour ce geste-là, une seule fois, une minute au plus ;
- seule `garde_compte_service(compte)` (ici `require_ai_ban`) le lit, en Bearer seulement. `require_jwt`,
  `require_session`, `require_lecture`, `require_personne` le refusent (`_validate_token` n'admet que HS256 ; le
  chemin du pilotage exige `sub = pilotage:…` et une `cible`) ; et `require_ai_ban` refuse toute session.

Refus : 401 (jeton absent, illisible, signature, clé inconnue, échéance, durée, frappé avant le démarrage, rejeu,
corps), 403 (audience d'une autre box, sujet, portée), 400/413 (corps de longueur illisible ou de plus de
`TAILLE_MAX_CORPS`, lu SEULEMENT après la signature), 503 (nom de box illisible, mémoire de rejeu pleine). Chaque
refus est audité (`audit.log`, motif, jamais le jeton), une ligne par (compte, motif) toutes les
`INTERVALLE_AUDIT_S` au plus, qui compte les refus retenus entre-temps (écrits au refus suivant ou par une minuterie).

CONTRAINTE SUR LES ROUTES (P9) : le jeton lie le CORPS, pas la méthode ni le chemin. Toute route gardée par un même
compte de service doit donc exiger dans son corps un champ OBLIGATOIRE qui la distingue de toutes les autres (et une
route sans corps, comme `GET /ai/etat`, n'avoir aucun effet) : sinon un jeton frappé pour une route vaudrait pour une
autre. À défaut, le jeton doit gagner des réclamations `methode` et `chemin`, vérifiées par la garde.

MÉMOIRE DE REJEU : en mémoire du processus, chaque `jti` gardé jusqu'à `exp + DERIVE_S`, `REJEU_MAX` au plus ; pleine,
elle REFUSE (503) au lieu d'oublier un `jti` encore valide. Un `jti` oublié l'est parce que son échéance est passée ;
l'horizon (plus haute échéance oubliée) refuse tout jeton qui n'est pas plus récent, même si l'horloge recule. Elle
suppose UN SEUL processus pour les routes gardées (agrégateur `--workers 1`). Un redémarrage la vide : tout jeton
dont l'`iat` précède le démarrage du processus (plus la dérive) est refusé (« avant_demarrage »).

CORPS LU AVANT LA GARDE : pour une route qui déclare un modèle de corps, FastAPI lit le corps AVANT de résoudre les
dépendances ; la garde le refuse ensuite au-delà de `TAILLE_MAX_CORPS`, mais la borne de lecture effective est alors
celle de l'amont (nginx `client_max_body_size`, sbxwaf). Une route sans modèle de corps n'est lue qu'après la
signature.
"""
from __future__ import annotations

import hashlib
import hmac
import os
import re
import secrets
import threading
import time
from typing import Any, Callable, Dict, Optional, Tuple

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials
from starlette.concurrency import run_in_threadpool

from . import auth

#: Arbre root des clés publiques, HORS de /etc/secubox (qui appartient au compte secubox).
DOSSIER_COMPTES_SERVICE = "/etc/secubox-comptes-service"
#: Liste FERMÉE des comptes de service et de leur portée unique.
COMPTES_SERVICE = {"ai-ban": "waf-ban"}
DUREE_MAX_S = 60
DERIVE_S = 5
ALGORITHME = "EdDSA"
#: Deux clés au plus à la fois (rotation) ; au-delà, aucune n'est reconnue.
CLES_MAX = 2
REJEU_MAX = 10_000
INTERVALLE_AUDIT_S = 10
#: Corps d'une requête gardée, au plus (413 au-delà) ; les gestes `ai-ban` tiennent en quelques centaines d'octets.
TAILLE_MAX_CORPS = 16 * 1024

_TAILLE_MAX_CLE = 4096
_TAILLE_MAX_JETON = 8192
#: Au-delà, le dossier est douteux : on ne lit pas un dossier rempli de fichiers.
_ENTREES_MAX = 64
_ENTETES_PERMIS = frozenset({"alg", "typ", "kid"})
_RECLAMATIONS = ("exp", "iat", "jti", "sub", "aud")
_RE_KID = re.compile(r"[0-9a-f]{64}")
_RE_NOM_CLE = re.compile(r"([0-9a-f]{64})\.pub")
_RE_JTI = re.compile(r"[0-9a-f]{32}")
_RE_HEX64 = re.compile(r"[0-9a-f]{64}")


class RefusCompteService(Exception):
    """Un jeton de compte de service refusé : `statut` HTTP (401, 403, 503) et `motif` machine-lisible, pris dans un
    ensemble FERMÉ (jamais une donnée du client : il part à l'audit et dans la réponse)."""

    def __init__(self, statut: int, motif: str):
        super().__init__(f"{statut} {motif}")
        self.statut = statut
        self.motif = motif


def _egal(a: Any, b: Any) -> bool:
    """Comparaison à temps constant de deux chaînes ; False si l'une n'en est pas une."""
    if not isinstance(a, str) or not isinstance(b, str):
        return False
    return hmac.compare_digest(a.encode("utf-8"), b.encode("utf-8"))


def _entier(v: Any) -> bool:
    return isinstance(v, int) and not isinstance(v, bool)


# ── Clés publiques ─────────────────────────────────────────────────────
def _empreinte_cle(cle: Ed25519PublicKey) -> str:
    der = cle.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    return hashlib.sha256(der).hexdigest()


def _charger_publique(pem: bytes) -> Ed25519PublicKey:
    try:
        cle = serialization.load_pem_public_key(pem)
    except Exception as e:  # noqa: BLE001 — PEM illisible, quelle qu'en soit la raison
        raise ValueError(f"clé publique illisible ({type(e).__name__})") from None
    if not isinstance(cle, Ed25519PublicKey):
        raise ValueError(f"clé publique {type(cle).__name__} : Ed25519 attendue")
    return cle


def empreinte(cle_publique_pem: bytes) -> str:
    """SHA-256 hex du DER SubjectPublicKeyInfo d'une clé publique Ed25519 en PEM (le `kid` et le nom du fichier).
    Lève ValueError si ce n'est pas une clé publique Ed25519."""
    return _empreinte_cle(_charger_publique(cle_publique_pem))


#: compte → (signature du dossier, {kid: clé}).
_cache_cles: Dict[str, Tuple[Any, Dict[str, Ed25519PublicKey]]] = {}
_verrou_cles = threading.Lock()


def _ouvrir_dossier_root(chemin: str, dir_fd: Optional[int] = None, complet: str = "") -> Tuple[int, os.stat_result]:
    """Un dossier de confiance ouvert `O_DIRECTORY|O_NOFOLLOW` (relatif à `dir_fd` s'il est donné ; `complet` = son
    chemin complet) : à `auth._proprietaire_attendu`, sans écriture pour le groupe ni les autres. Lève OSError ou
    ValueError."""
    complet = complet or chemin
    fd = os.open(chemin, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=dir_fd)
    try:
        sd = os.fstat(fd)
        if sd.st_uid != auth._proprietaire_attendu(complet) or sd.st_mode & 0o022:
            raise ValueError(f"dossier {complet!r} : pas à root, ou inscriptible par le groupe ou les autres")
        return fd, sd
    except BaseException:
        os.close(fd)
        raise


def _releve_dossier(compte: str) -> Tuple[str, Any, list]:
    """(chemin du dossier du compte, signature, noms candidats). La signature change dès qu'une entrée candidate
    apparaît, disparaît ou change (inode, taille, `mtime_ns`, droits), ou que le dossier change (inode, `mtime_ns`) :
    un retrait de clé prend effet à la requête suivante, sans dépendre de la finesse de l'horodatage."""
    racine = DOSSIER_COMPTES_SERVICE
    dossier = os.path.join(racine, compte)
    rfd, sr = _ouvrir_dossier_root(racine)
    try:
        cfd, sc = _ouvrir_dossier_root(compte, dir_fd=rfd, complet=dossier)
    finally:
        os.close(rfd)
    try:
        noms = os.listdir(cfd)
        if len(noms) > _ENTREES_MAX:
            raise ValueError(f"dossier {dossier!r} : {len(noms)} entrées (> {_ENTREES_MAX})")
        candidats = []
        for nom in sorted(noms):
            if not _RE_NOM_CLE.fullmatch(nom):
                continue
            s = os.stat(nom, dir_fd=cfd, follow_symlinks=False)
            candidats.append((nom, s.st_ino, s.st_size, s.st_mtime_ns, s.st_mode, s.st_uid))
    finally:
        os.close(cfd)
    signature = (sr.st_dev, sr.st_ino, sc.st_ino, sc.st_mtime_ns, sc.st_mode, sc.st_uid, tuple(candidats))
    return dossier, signature, [c[0] for c in candidats]


def cles_publiques(compte: str) -> Dict[str, Ed25519PublicKey]:
    """Les clés publiques reconnues du compte, `{kid: clé}` : fichiers `<kid>.pub` du dossier du compte dont le nom
    est l'empreinte RÉELLE de la clé Ed25519 qu'ils contiennent. Un fichier douteux (lien, propriétaire, droits,
    taille, autre type, nom ≠ empreinte) est ignoré, avec un avertissement ; un dossier douteux, ou plus de `CLES_MAX`
    clés valides ⇒ `{}` (aucun jeton reconnu). Relu quand le dossier change."""
    if compte not in COMPTES_SERVICE:
        return {}
    try:
        dossier, signature, noms = _releve_dossier(compte)
    except (OSError, ValueError) as e:
        auth._avertir_une_fois(("compte-service", compte, str(e)), "compte de service %r : dossier refusé : %r",
                               compte, str(e))
        return {}
    with _verrou_cles:
        en_cache = _cache_cles.get(compte)
        if en_cache is not None and en_cache[0] == signature:
            return dict(en_cache[1])
    cles: Dict[str, Ed25519PublicKey] = {}
    for nom in noms:
        try:
            donnees, _ = auth._lire_fichier_root(dossier, nom, _TAILLE_MAX_CLE)
            cle = _charger_publique(donnees)
            kid = _empreinte_cle(cle)
            if not _egal(f"{kid}.pub", nom):
                raise ValueError(f"nom {nom!r} ≠ empreinte {kid}")
        except (OSError, ValueError) as e:
            auth._avertir_une_fois(("compte-service", compte, nom, str(e)),
                                   "compte de service %r : clé %r ignorée : %r", compte, nom, str(e))
            continue
        cles[kid] = cle
    if len(cles) > CLES_MAX:
        auth._avertir_une_fois(("compte-service", compte, "trop", signature),
                               "compte de service %r : %d clés (> %d) : aucune n'est reconnue",
                               compte, len(cles), CLES_MAX)
        cles = {}
    with _verrou_cles:
        _cache_cles[compte] = (signature, cles)
    return dict(cles)


# ── Mémoire de rejeu ───────────────────────────────────────────────────
class _Rejeu:
    """`jti` déjà servis, chacun jusqu'à sa fin (`exp + DERIVE_S`). Partagée entre fils (gardes en pool)."""

    def __init__(self) -> None:
        self._fins: Dict[str, float] = {}
        self._horizon = float("-inf")   # plus haute fin d'un jti oublié
        self._verrou = threading.Lock()

    def __len__(self) -> int:
        return len(self._fins)

    def _purger(self, maintenant: float) -> None:
        echus = [j for j, fin in self._fins.items() if fin <= maintenant]
        for j in echus:
            self._horizon = max(self._horizon, self._fins.pop(j))

    def deja_vu(self, jti: str, fin: float) -> bool:
        with self._verrou:
            return jti in self._fins or fin <= self._horizon

    def consommer(self, jti: str, fin: float, maintenant: float) -> None:
        """Inscrit le `jti`, atomiquement ; lève `rejeu` (401) s'il est déjà vu, `rejeu_plein` (503) sans place."""
        with self._verrou:
            self._purger(maintenant)
            if jti in self._fins or fin <= self._horizon:
                raise RefusCompteService(401, "rejeu")
            if len(self._fins) >= REJEU_MAX:
                raise RefusCompteService(503, "rejeu_plein")
            self._fins[jti] = fin


_rejeu = _Rejeu()
#: Démarrage du processus : un jeton frappé avant (à la dérive près) est refusé, la mémoire de rejeu étant neuve.
_DEMARRAGE = time.time()


# ── Jetons ─────────────────────────────────────────────────────────────
def frapper_jeton(cle_privee_pem: bytes, compte: str, aud: str, corps: bytes, maintenant: float,
                  duree_s: int = 30) -> str:
    """Le jeton d'UNE requête (côté box de l'IA ; gk2 n'a jamais la clé privée). Lève ValueError sur un compte hors
    liste, une durée hors `]0, DUREE_MAX_S]` ou une clé qui n'est pas une clé privée Ed25519."""
    if compte not in COMPTES_SERVICE:
        raise ValueError(f"compte de service inconnu : {compte!r}")
    if not _entier(duree_s) or not 0 < duree_s <= DUREE_MAX_S:
        raise ValueError(f"durée {duree_s!r} hors de ]0, {DUREE_MAX_S}]")
    try:
        cle = serialization.load_pem_private_key(cle_privee_pem, password=None)
    except Exception as e:  # noqa: BLE001
        raise ValueError(f"clé privée illisible ({type(e).__name__})") from None
    if not isinstance(cle, Ed25519PrivateKey):
        raise ValueError(f"clé privée {type(cle).__name__} : Ed25519 attendue")
    iat = int(maintenant)
    reclamations = {"sub": compte, "aud": aud, "portee": COMPTES_SERVICE[compte], "iat": iat, "exp": iat + duree_s,
                    "jti": secrets.token_hex(16), "corps": hashlib.sha256(corps).hexdigest()}
    return jwt.encode(reclamations, cle, algorithm=ALGORITHME, headers={"kid": _empreinte_cle(cle.public_key())})


def _verifier_avant_corps(compte: str, jeton: str, maintenant: float) -> Tuple[str, str, float, str]:
    """Tout ce qui ne dépend pas du corps : en-tête, clé, signature, réclamations, `jti` non vu. Rend
    `(kid, jti, fin, empreinte du corps signée)`. Lève `RefusCompteService`."""
    portee_attendue = COMPTES_SERVICE.get(compte)
    if portee_attendue is None:
        raise RefusCompteService(401, "compte")
    if not isinstance(jeton, str) or not jeton or len(jeton) > _TAILLE_MAX_JETON:
        raise RefusCompteService(401, "illisible")
    try:
        entete = jwt.get_unverified_header(jeton)
    except (jwt.PyJWTError, ValueError, TypeError):
        raise RefusCompteService(401, "illisible") from None
    if not isinstance(entete, dict) or not set(entete) <= _ENTETES_PERMIS:
        raise RefusCompteService(401, "entete")
    if not _egal(entete.get("alg"), ALGORITHME):
        raise RefusCompteService(401, "algorithme")
    if "typ" in entete and not _egal(entete.get("typ"), "JWT"):
        raise RefusCompteService(401, "entete")
    kid = entete.get("kid")
    cle = None
    if isinstance(kid, str) and _RE_KID.fullmatch(kid):
        for k, c in cles_publiques(compte).items():
            if _egal(k, kid):
                cle = c
    if cle is None:
        raise RefusCompteService(401, "cle_inconnue")
    box = auth.nom_box_locale()
    if not box:
        raise RefusCompteService(503, "box_inconnue")
    try:
        # Signature et audience par PyJWT ; les instants (exp, iat, nbf) sont vérifiés À LA MAIN ci-dessous, dérive
        # `DERIVE_S` comprise, contre `maintenant` : une seule horloge, celle de l'appelant (pas de `leeway`).
        p = jwt.decode(jeton, cle, algorithms=[ALGORITHME], audience=box,
                       options={"require": list(_RECLAMATIONS), "verify_exp": False, "verify_iat": False,
                                "verify_nbf": False})
    except jwt.InvalidSignatureError:
        raise RefusCompteService(401, "signature") from None
    except jwt.MissingRequiredClaimError:
        raise RefusCompteService(401, "reclamations") from None
    except jwt.InvalidAudienceError:
        raise RefusCompteService(403, "audience") from None
    except (jwt.PyJWTError, ValueError, TypeError):
        raise RefusCompteService(401, "illisible") from None
    if not isinstance(p, dict):
        raise RefusCompteService(401, "illisible")
    if not _egal(p.get("aud"), box):   # une chaîne, pas une liste qui la contiendrait
        raise RefusCompteService(403, "audience")
    if not _egal(p.get("sub"), compte):
        raise RefusCompteService(403, "sujet")
    if not _egal(p.get("portee"), portee_attendue):
        raise RefusCompteService(403, "portee")
    iat, exp, nbf = p.get("iat"), p.get("exp"), p.get("nbf")
    if not _entier(iat) or not _entier(exp) or (nbf is not None and not _entier(nbf)):
        raise RefusCompteService(401, "reclamations")
    if not 0 < exp - iat <= DUREE_MAX_S:
        raise RefusCompteService(401, "duree")
    if iat > maintenant + DERIVE_S or (nbf is not None and nbf > maintenant + DERIVE_S):
        raise RefusCompteService(401, "iat_futur")
    if iat < _DEMARRAGE + DERIVE_S:
        # Frappé avant ce processus (à la dérive près) : sa mémoire de rejeu, neuve, ne peut pas dire s'il a servi.
        raise RefusCompteService(401, "avant_demarrage")
    fin = exp + DERIVE_S
    if fin <= maintenant:
        raise RefusCompteService(401, "echu")
    jti = p.get("jti")
    if not isinstance(jti, str) or not _RE_JTI.fullmatch(jti):
        raise RefusCompteService(401, "jti")
    if _rejeu.deja_vu(jti, fin):
        raise RefusCompteService(401, "rejeu")
    empreinte_corps = p.get("corps")
    if not isinstance(empreinte_corps, str) or not _RE_HEX64.fullmatch(empreinte_corps):
        raise RefusCompteService(401, "reclamations")
    return kid, jti, fin, empreinte_corps


def _verifier_corps(compte: str, verifie: Tuple[str, str, float, str], corps: bytes,
                    maintenant: float) -> Dict[str, Any]:
    """Empreinte du corps, puis inscription atomique du `jti`. Lève `RefusCompteService`."""
    kid, jti, fin, empreinte_corps = verifie
    if not _egal(empreinte_corps, hashlib.sha256(corps).hexdigest()):
        raise RefusCompteService(401, "corps")
    _rejeu.consommer(jti, fin, maintenant)
    return {"sub": compte, "compte_service": compte, "jti": jti, "cle": kid}


def verifier_jeton(compte: str, jeton: str, corps: bytes, maintenant: float) -> Dict[str, Any]:
    """`{"sub", "compte_service", "jti", "cle"}` d'un jeton valide pour `compte` et ce `corps` exact, à l'instant
    `maintenant` (secondes UNIX) ; consomme son `jti`. Lève `RefusCompteService` sinon.

    Ordre : en-tête non vérifié (`alg`, `kid` connu) → signature et audience → sujet → portée → durée, `iat`, frappé
    après le démarrage, échéance → `jti` (forme, non vu) → empreinte du corps → inscription atomique du `jti`. Un
    corps refusé ne consomme pas le `jti` : rejouer un jeton capturé avec un autre corps ne brûle pas le geste
    légitime."""
    return _verifier_corps(compte, _verifier_avant_corps(compte, jeton, maintenant), corps, maintenant)


async def _lire_corps_borne(request: Request) -> bytes:
    """Le corps brut, `TAILLE_MAX_CORPS` au plus : 413 sur `Content-Length` annoncé trop grand, et sur la longueur
    réellement lue (lecture arrêtée au dépassement) ; 400 sur un `Content-Length` illisible. Le corps lu est remis en
    cache (`request._body`, comme le fait `Request.body()` de Starlette) pour la route."""
    longueur = request.headers.get("content-length")
    if longueur is not None:
        if not longueur.strip().isdigit():
            raise RefusCompteService(400, "longueur")
        if int(longueur) > TAILLE_MAX_CORPS:
            raise RefusCompteService(413, "corps_trop_grand")
    if hasattr(request, "_body"):   # déjà lu (route à modèle de corps : FastAPI le lit avant les dépendances)
        corps = request._body
        if len(corps) > TAILLE_MAX_CORPS:
            raise RefusCompteService(413, "corps_trop_grand")
        return corps
    morceaux, total = [], 0
    async for morceau in request.stream():
        total += len(morceau)
        if total > TAILLE_MAX_CORPS:
            raise RefusCompteService(413, "corps_trop_grand")
        morceaux.append(morceau)
    corps = b"".join(morceaux)
    request._body = corps
    return corps


# ── Audit des refus ────────────────────────────────────────────────────
#: (compte, motif) → [instant de la dernière ligne, refus non encore écrits, dernière adresse] ; borné : compte et
#: motif sont des ensembles fermés.
_derniers_refus: Dict[Tuple[str, str], list] = {}
_verrou_audit = threading.Lock()
#: La minuterie qui écrit les refus restés en attente (fin d'une rafale), armée tant qu'il en reste.
_minuterie: Dict[str, Any] = {"active": None}


def _horloge() -> float:
    return time.monotonic()


def _ligne_refus(compte: str, motif: str, ip: str, nombre: int) -> Dict[str, Any]:
    return {"ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "module": "compte-service", "action": "refus",
            "compte": compte, "motif": motif, "ip": str(ip)[:64], "nombre": nombre}


def _ecrire_lignes(lignes: list) -> None:
    for ligne in lignes:
        try:
            auth._ecrire_audit(ligne)
        except Exception as e:  # noqa: BLE001 — un audit impossible ne change pas le refus, mais se dit
            auth._avertir_une_fois(("compte-service", "audit", type(e).__name__),
                                   "compte de service : audit impossible : %r", type(e).__name__)


def _echues(instant: float) -> list:
    """Sous `_verrou_audit` : les lignes des refus en attente dont la fenêtre est passée (et les remet à zéro)."""
    lignes = []
    for (compte, motif), etat in _derniers_refus.items():
        if etat[1] and instant - etat[0] >= INTERVALLE_AUDIT_S:
            lignes.append(_ligne_refus(compte, motif, etat[2], etat[1]))
            etat[0], etat[1] = instant, 0
    return lignes


def _armer_minuterie() -> None:
    """Sous `_verrou_audit` : une minuterie (fil démon) écrira les refus en attente, même sans nouveau refus."""
    if _minuterie["active"] is not None:
        return
    m = threading.Timer(INTERVALLE_AUDIT_S, _vider_en_attente)
    m.daemon = True
    _minuterie["active"] = m
    m.start()


def _vider_en_attente() -> None:
    """Écrit les refus en attente dont la fenêtre est passée ; se réarme s'il en reste."""
    with _verrou_audit:
        _minuterie["active"] = None
        lignes = _echues(_horloge())
        if any(etat[1] for etat in _derniers_refus.values()):
            _armer_minuterie()
    _ecrire_lignes(lignes)


def _auditer_refus(compte: str, motif: str, ip: str) -> None:
    """Une ligne `audit.log` par (compte, motif) toutes les `INTERVALLE_AUDIT_S` au plus, avec le nombre de refus
    qu'elle résume. Les refus retenus pendant la fenêtre sont écrits au refus suivant (de tout motif) ou par la
    minuterie : chaque refus est compté. Jamais le jeton, ni le corps."""
    instant = _horloge()
    with _verrou_audit:
        etat = _derniers_refus.get((compte, motif))
        if etat is None:
            _derniers_refus[(compte, motif)] = [instant, 0, ip]
            lignes = [_ligne_refus(compte, motif, ip, 1)]
        else:
            etat[1] += 1
            etat[2] = ip
            lignes = []
        lignes += _echues(instant)
        if any(e[1] for e in _derniers_refus.values()):
            _armer_minuterie()
    _ecrire_lignes(lignes)


def _refus_http(compte: str, refus: RefusCompteService, request: Request) -> HTTPException:
    try:
        ip = auth.adresse_client(request)
    except Exception:  # noqa: BLE001
        ip = ""
    _auditer_refus(compte, refus.motif, ip)
    entetes = {"WWW-Authenticate": "Bearer"} if refus.statut == status.HTTP_401_UNAUTHORIZED else None
    return HTTPException(status_code=refus.statut, detail=f"Jeton de compte de service refusé : {refus.motif}",
                         headers=entetes)


def garde_compte_service(compte: str) -> Callable[..., Any]:
    """La dépendance FastAPI d'un compte de service de la liste fermée (ValueError sinon). Bearer SEULEMENT (jamais le
    cookie de session). Vérifie en-tête, clé, signature et réclamations AVANT de lire le corps, puis le lit borné
    (`TAILLE_MAX_CORPS`), puis compare son empreinte et consomme le `jti`."""
    if compte not in COMPTES_SERVICE:
        raise ValueError(f"compte de service inconnu : {compte!r}")

    async def garde(request: Request,
                    creds: Optional[HTTPAuthorizationCredentials] = Depends(auth._bearer)) -> Dict[str, Any]:
        jeton = creds.credentials if creds is not None and creds.credentials else ""
        maintenant = time.time()
        try:
            if not jeton:
                raise RefusCompteService(401, "absent")
            # Lecture des clés et vérification Ed25519 hors de la boucle (RULES-CODE § 6).
            verifie = await run_in_threadpool(_verifier_avant_corps, compte, jeton, maintenant)
            corps = await _lire_corps_borne(request)
            return await run_in_threadpool(_verifier_corps, compte, verifie, corps, maintenant)
        except RefusCompteService as refus:
            exc = await run_in_threadpool(_refus_http, compte, refus, request)
        raise exc

    garde.__name__ = f"require_{compte.replace('-', '_')}"
    return garde


require_ai_ban = garde_compte_service("ai-ban")

__all__ = ["DOSSIER_COMPTES_SERVICE", "COMPTES_SERVICE", "DUREE_MAX_S", "DERIVE_S", "ALGORITHME", "CLES_MAX",
           "REJEU_MAX", "TAILLE_MAX_CORPS", "RefusCompteService", "empreinte", "cles_publiques", "verifier_jeton", "frapper_jeton",
           "garde_compte_service", "require_ai_ban"]
