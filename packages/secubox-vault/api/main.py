# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""SecuBox-Deb :: secubox-vault 2.0 — API du Coffre (#1367 P1).

DEUX APPLICATIONS, DEUX SOCKETS, UN SEUL COFFRE.

- `public` (/run/secubox/vault.sock) : relayée par l'agrégateur aux seuls
  administrateurs réels. Ouvrir, sceller, état, NOMS des secrets, poser,
  retirer, journal. Elle ne rend JAMAIS la valeur d'un secret de la box : pas
  d'oracle derrière une session web.
- `/moi/…` sur la même socket (P5) : relayée à toute PERSONNE SBX OS. Le Coffre
  reconnaît la personne lui-même, depuis la session (aucun en-tête n'en
  décide) ; chaque requête qui touche une valeur apporte SA serrure — phrase
  ou sortie PRF — et une personne ne relit que ses propres secrets. Hors LAN (ou sous politique « second facteur
  obligatoire »), l'ouverture exige un TOTP frais, vérifié par l'AGRÉGATEUR —
  lui seul peut tenir le plancher anti-rejeu — qui le signale par l'en-tête
  X-SecuBox-Second-Facteur (P4) ; chaque ouverture distante envoie une alerte
  courriel. Cinq échecs par heure et par identité, puis 429.
- `/compte/…` sur la même socket (#1855) : la CONNEXION d'un administrateur
  rejoue son mot de passe — préparer au mot de passe vérifié, confirmer au
  second facteur réussi. Sans jeton (c'est la connexion elle-même) : le
  Coffre revérifie le mot de passe dans users.json et le rôle d'admin, et
  refuse tout ce qui arrive par le relais web de l'agrégateur.
- `racine` (/run/secubox-coffre/racine.sock, répertoire 0700) : celle de
  `coffrectl`, pour root. Initialisation, lecture d'une valeur, serrures,
  codes de secours. Le système de fichiers est la garde.

Le Coffre ne vit QUE dans ce processus : jamais monté dans l'agrégateur, dont
tous les modules partagent la mémoire.
"""
import base64
import os
import secrets as _alea
import threading
import time
from datetime import datetime, timezone
from collections import defaultdict, deque
from pathlib import Path
from typing import Optional

from fastapi import Depends, FastAPI, HTTPException, Request
from pydantic import BaseModel, Field
from secubox_core import second_facteur
# `/moi` : une SESSION, invités compris (#1855) — la personne est celle du jeton
# (`_personne` : 403 sans personne SBX OS), et son compartiment n'a que SES serrures.
from secubox_core.auth import require_jwt, require_session

from coffre.coffre import Coffre, Interdit, NonInitialise, RefusPersonnel, Scelle, b64u, b64u_decode
from coffre.crypto import Refus
from coffre.journal import Journal

VERSION = "2.0.0"
BASE = Path(os.environ.get("SECUBOX_COFFRE_DIR", "/var/lib/secubox/coffre"))
JOURNAL = Path(os.environ.get("SECUBOX_COFFRE_JOURNAL", "/var/log/secubox/coffre.journal"))
DELAI_S = int(os.environ.get("SECUBOX_COFFRE_DELAI_S", "900"))

COFFRE = Coffre(BASE, Journal(JOURNAL), delai_s=DELAI_S)

ENTETE_SECOND_FACTEUR = "X-SecuBox-Second-Facteur"   # posé par l'agrégateur, après le TOTP
ESSAIS_MAX = 5
FENETRE_S = 3600
_echecs: dict = defaultdict(deque)


class Ouverture(BaseModel):
    secret: str = Field(min_length=1, max_length=1024)
    genre: str = "phrase"
    cred_id: Optional[str] = Field(default=None, max_length=1024)
    otp: Optional[str] = Field(default=None, max_length=10)   # lu par l'agrégateur, pas ici


class Appareil(BaseModel):
    cred_id: str = Field(min_length=16, max_length=1024)
    sel: str = Field(min_length=40, max_length=64)
    prf: str = Field(min_length=40, max_length=64)
    libelle: str = Field(default="", max_length=80)


class OuverturePerso(BaseModel):
    """La serrure de la personne : phrase, sortie PRF (base64url) + cred_id, ou
    `session` — la clé tenue depuis sa connexion (#1855), sans rien à taper."""
    secret: str = Field(default="", max_length=1024)
    genre: str = "phrase"
    cred_id: Optional[str] = Field(default=None, max_length=1024)


class PersoInit(BaseModel):
    phrase: str = Field(min_length=1, max_length=1024)
    libelle: str = Field(default="", max_length=80)


class PersoPhrase(BaseModel):
    ouverture: OuverturePerso
    phrase: str = Field(min_length=1, max_length=1024)
    libelle: str = Field(default="", max_length=80)


class PersoAppareil(BaseModel):
    ouverture: OuverturePerso
    cred_id: str = Field(min_length=16, max_length=1024)
    sel: str = Field(min_length=40, max_length=64)
    prf: str = Field(min_length=40, max_length=64)
    libelle: str = Field(default="", max_length=80)


class PersoAcces(BaseModel):
    ouverture: OuverturePerso


class PersoPose(BaseModel):
    ouverture: OuverturePerso
    nom: str = Field(max_length=64)
    valeur: str = Field(min_length=1, max_length=65536)


class PersoCompte(BaseModel):
    ouverture: OuverturePerso
    mot_de_passe: str = Field(min_length=1, max_length=1024)
    libelle: str = Field(default="", max_length=80)


class PersoOpenPGP(BaseModel):
    ouverture: OuverturePerso
    nom: str = Field(min_length=1, max_length=64)
    courriel: str = Field(min_length=3, max_length=254)


class Detenteurs(BaseModel):
    detenteurs: list[str] = Field(min_length=2, max_length=5)


class Parts(BaseModel):
    parts: list[str] = Field(min_length=2, max_length=5)


class Compte(BaseModel):
    utilisateur: str = Field(min_length=1, max_length=64)
    mot_de_passe: str = Field(min_length=1, max_length=1024)


class Ticket(BaseModel):
    ticket: str = Field(min_length=20, max_length=128)
    distante: bool = False      # connexion hors LAN : la boîte de la box est prévenue


class Changement(BaseModel):
    utilisateur: str = Field(min_length=1, max_length=64)
    ancien: str = Field(min_length=1, max_length=1024)
    nouveau: str = Field(min_length=1, max_length=1024)


class Pose(BaseModel):
    compartiment: str = Field(max_length=40)
    nom: str = Field(max_length=64)
    valeur: str = Field(min_length=1, max_length=65536)


class Phrase(BaseModel):
    phrase: str = Field(min_length=1, max_length=1024)
    libelle: str = Field(default="", max_length=80)


class Compartiment(BaseModel):
    id: str = Field(max_length=40)
    libelle: str = Field(default="", max_length=80)


def _traduit(e: Exception) -> HTTPException:
    if isinstance(e, RefusPersonnel):
        return HTTPException(403, "serrure refusée")
    if isinstance(e, Scelle):
        return HTTPException(423, "Coffre scellé")
    if isinstance(e, NonInitialise):
        return HTTPException(409, "Coffre non initialisé")
    if isinstance(e, Interdit):
        return HTTPException(400, str(e))
    if isinstance(e, KeyError):
        return HTTPException(404, "secret inconnu")
    if isinstance(e, Refus):
        COFFRE.journal.ajouter("integrite", detail="déchiffrement refusé")
        return HTTPException(500, "intégrité : secret illisible")
    raise e


def _appel(fn, *a, **k):
    try:
        return fn(*a, **k)
    except (Scelle, NonInitialise, Interdit, KeyError, Refus, RefusPersonnel) as e:
        raise _traduit(e) from None


def _limite(qui: str) -> None:
    q = _echecs[qui]
    while q and time.monotonic() - q[0] > FENETRE_S:
        q.popleft()
    if len(q) >= ESSAIS_MAX:
        raise HTTPException(429, "trop d'essais — réessayer plus tard")


def _routes_communes(app: FastAPI, garde: list) -> None:
    @app.get("/health")
    def health():
        return {"status": "ok", "module": "vault", "version": VERSION}

    @app.get("/etat", dependencies=garde)
    def etat():
        return COFFRE.etat()

    @app.post("/sceller", dependencies=garde)
    def sceller():
        COFFRE.sceller("commande")
        return COFFRE.etat()

    @app.get("/secrets", dependencies=garde)
    def secrets(compartiment: Optional[str] = None):
        return {"secrets": _appel(COFFRE.lister, compartiment)}

    @app.post("/secrets", dependencies=garde)
    def poser(p: Pose):
        return {"version": _appel(COFFRE.poser, p.compartiment, p.nom, p.valeur.encode())}

    @app.delete("/secrets/{compartiment}/{nom}", dependencies=garde)
    def retirer(compartiment: str, nom: str):
        _appel(COFFRE.retirer, compartiment, nom)
        return {"retire": True}

    @app.get("/journal", dependencies=garde)
    def journal(n: int = 50):
        integre, fautive, lignes = COFFRE.journal.verifier()
        return {"integre": integre, "ligne_fautive": fautive, "lignes": lignes,
                "entrees": COFFRE.journal.derniers(max(1, min(n, 500)))}


# ── public : administrateurs réels, via l'agrégateur ──────────────────────────
public = FastAPI(title="SecuBox Coffre", version=VERSION, docs_url=None, redoc_url=None, openapi_url=None)
_routes_communes(public, [Depends(require_jwt)])


@public.post("/ouvrir")
def ouvrir_public(o: Ouverture, request: Request, user=Depends(require_jwt)):
    qui = str((user or {}).get("sub") or "?")
    _limite(qui)
    distante = request.headers.get("X-SecuBox-LAN", "").strip() != "1"
    if second_facteur.otp_exige(request) and request.headers.get(ENTETE_SECOND_FACTEUR) != "verifie":
        _echecs[qui].append(time.monotonic())
        COFFRE.journal.ajouter("ouverture_refusee", genre=o.genre, qui=qui, motif="second_facteur")
        raise HTTPException(401, "second facteur exigé (code TOTP)")
    origine = "distante" if distante else "lan"
    ok = _appel(COFFRE.ouvrir, o.secret, o.genre, o.cred_id, qui=qui, origine=origine)
    if not ok:
        _echecs[qui].append(time.monotonic())
        raise HTTPException(403, "refusé")
    _echecs.pop(qui, None)
    if distante:
        threading.Thread(target=_alerte_distante, args=(qui,), daemon=True).start()
    return COFFRE.etat()


def _alerte_distante(qui: str) -> None:
    """Chaque ouverture hors LAN prévient la boîte de la box (§4)."""
    try:
        from secubox_core import courriel
        dest = courriel.adresse_de_la_box()
        if not dest:
            COFFRE.journal.ajouter("alerte_non_envoyee", motif="aucune adresse de box")
            return
        quand = datetime.now(timezone.utc).isoformat(timespec="seconds")
        courriel.envoie(dest, "[SecuBox] Coffre ouvert à distance",
                        f"Le Coffre a été ouvert hors du LAN par « {qui} » le {quand}.\n\n"
                        "Si ce n'est pas vous : scellez-le (page Coffre, ou coffrectl sceller en SSH)\n"
                        "et changez sa phrase.\n")
        COFFRE.journal.ajouter("alerte_envoyee", qui=qui)
    except Exception as e:  # noqa: BLE001 — l'alerte ne doit jamais faire tomber l'ouverture
        COFFRE.journal.ajouter("alerte_non_envoyee", motif=type(e).__name__)


# ── clés d'appareil (WebAuthn PRF, P4) ────────────────────────────────────────
@public.get("/serrures/appareil", dependencies=[Depends(require_jwt)])
def appareils():
    return {"appareils": COFFRE.serrures_appareil()}


@public.post("/serrures/appareil/preparer", dependencies=[Depends(require_jwt)])
def appareil_preparer():
    """Un sel neuf : l'authentificateur rendra une sortie PRF propre à ce sel."""
    return {"sel": b64u(_alea.token_bytes(32))}


@public.post("/serrures/appareil", dependencies=[Depends(require_jwt)])
def appareil_ajouter(a: Appareil):
    try:
        sel, prf = b64u_decode(a.sel), b64u_decode(a.prf)
    except (ValueError, TypeError):
        raise HTTPException(400, "sel ou sortie PRF illisible") from None
    return {"id": _appel(COFFRE.ajouter_serrure_appareil, a.cred_id, sel, prf, a.libelle)}


@public.delete("/serrures/appareil/{ident}", dependencies=[Depends(require_jwt)])
def appareil_retirer(ident: str):
    if not any(x["id"] == ident for x in COFFRE.serrures_appareil()):
        raise HTTPException(404, "clé d'appareil inconnue")
    _appel(COFFRE.retirer_serrure, ident)
    return {"retiree": True}


# ── compartiment de la personne (P5) ──────────────────────────────────────────
def _personne(user: dict) -> str:
    """La personne SBX OS derrière la session — calculée ICI, depuis le jeton
    vérifié : aucun en-tête relayé n'en décide."""
    from secubox_core import capacites
    p = capacites.personne_du_porteur(user or {})
    if not p or not p.get("user_uuid"):
        raise HTTPException(403, "aucune personne SBX OS derrière cette session")
    return str(p["user_uuid"])


def _perso(user: dict, fn, *a):
    """Appelle `fn(personne, …)` sous la limite d'essais de la personne : une
    serrure refusée compte, cinq par heure, puis 429."""
    personne = _personne(user)
    cle = "moi:" + personne
    _limite(cle)
    try:
        r = fn(personne, *a)
    except RefusPersonnel:
        _echecs[cle].append(time.monotonic())
        raise HTTPException(403, "serrure refusée") from None
    except (Scelle, NonInitialise, Interdit, KeyError, Refus) as e:
        raise _traduit(e) from None
    return r


def _ouv(o: OuverturePerso) -> dict:
    return {"secret": o.secret, "genre": o.genre, "cred_id": o.cred_id}


@public.get("/moi")
def moi(user=Depends(require_session)):
    return _perso(user, COFFRE.personne_etat)


@public.post("/moi/initialiser")
def moi_initialiser(p: PersoInit, user=Depends(require_session)):
    _perso(user, COFFRE.personne_initialiser, p.phrase, p.libelle)
    return _perso(user, COFFRE.personne_etat)


@public.post("/moi/serrures/compte")
def moi_compte(p: PersoCompte, user=Depends(require_session)):
    """Relier le mot de passe de connexion à la personne : désormais sa
    connexion ouvre son compartiment, sans phrase. Le mot de passe est vérifié
    contre le COMPTE de la session — jamais contre un nom venu de la requête."""
    from secubox_core import user_store  # noqa: PLC0415
    sub = str((user or {}).get("sub", ""))
    if not sub or sub.startswith("sbx-") or not user_store.verify_password(sub, p.mot_de_passe):
        raise HTTPException(403, "mot de passe de connexion refusé")
    return {"id": _perso(user, COFFRE.personne_ajouter_compte, _ouv(p.ouverture), p.mot_de_passe, p.libelle)}


@public.post("/moi/fermer")
def moi_fermer(user=Depends(require_session)):
    """« Verrouiller » : la clé tenue pour cette personne est oubliée."""
    _perso(user, COFFRE.personne_fermer)
    return {"ferme": True}


@public.post("/moi/serrures/phrase")
def moi_phrase(p: PersoPhrase, user=Depends(require_session)):
    return {"id": _perso(user, COFFRE.personne_ajouter_phrase, _ouv(p.ouverture), p.phrase, p.libelle)}


@public.post("/moi/serrures/appareil/preparer")
def moi_appareil_preparer(user=Depends(require_session)):
    _personne(user)
    return {"sel": b64u(_alea.token_bytes(32))}


@public.post("/moi/serrures/appareil")
def moi_appareil(a: PersoAppareil, user=Depends(require_session)):
    try:
        sel, prf = b64u_decode(a.sel), b64u_decode(a.prf)
    except (ValueError, TypeError):
        raise HTTPException(400, "sel ou sortie PRF illisible") from None
    return {"id": _perso(user, COFFRE.personne_ajouter_appareil, _ouv(a.ouverture), a.cred_id, sel, prf,
                         a.libelle)}


@public.post("/moi/serrures/{ident}/retirer")
def moi_serrure_retirer(ident: str, a: PersoAcces, user=Depends(require_session)):
    _perso(user, COFFRE.personne_retirer_serrure, _ouv(a.ouverture), ident)
    return {"retiree": True}


@public.post("/moi/secrets/lister")
def moi_lister(a: PersoAcces, user=Depends(require_session)):
    return {"secrets": _perso(user, COFFRE.personne_lister, _ouv(a.ouverture))}


@public.post("/moi/secrets")
def moi_poser(p: PersoPose, user=Depends(require_session)):
    return {"version": _perso(user, COFFRE.personne_poser, _ouv(p.ouverture), p.nom, p.valeur.encode())}


@public.post("/moi/secrets/{nom}/lire")
def moi_lire(nom: str, a: PersoAcces, user=Depends(require_session)):
    """La personne relit SON secret, avec SA serrure dans la même requête."""
    v = _perso(user, COFFRE.personne_lire, _ouv(a.ouverture), nom)
    return {"valeur": v.decode("utf-8", "replace")}


@public.post("/moi/secrets/{nom}/retirer")
def moi_retirer(nom: str, a: PersoAcces, user=Depends(require_session)):
    _perso(user, COFFRE.personne_retirer, _ouv(a.ouverture), nom)
    return {"retire": True}


@public.post("/moi/openpgp")
def moi_openpgp(p: PersoOpenPGP, user=Depends(require_session)):
    """Une clé OpenPGP pour la personne, née ici et rangée dans son coffre."""
    return _perso(user, COFFRE.personne_openpgp_creer, _ouv(p.ouverture), p.nom, p.courriel)


# ── la connexion de l'administrateur ouvre le Coffre (#1855) ───────────────────
ENTETE_RELAIS = "X-SecuBox-Relais"          # posé par l'agrégateur sur son relais web


def _hors_relais(request: Request) -> None:
    """Ces routes ne servent que secubox-auth, par la socket : jamais le web."""
    if request.headers.get(ENTETE_RELAIS):
        raise HTTPException(404)


def _personne_de_compte(utilisateur: str) -> Optional[str]:
    """La personne SBX OS d'un compte (la même règle que le Hall) — ou None."""
    try:
        from secubox_core import capacites  # noqa: PLC0415
        p = capacites.personne_du_porteur({"sub": utilisateur})
        return str(p["user_uuid"]) if p and p.get("user_uuid") else None
    except Exception:  # noqa: BLE001 — une personne introuvable n'empêche jamais une connexion
        return None


def _compte_au_mot_de_passe(utilisateur: str, mot_de_passe: str) -> bool:
    """Un compte SYSTÈME existant, ouvert, au bon mot de passe — administrateur ou non."""
    from secubox_core import user_store  # noqa: PLC0415
    u = user_store.get_user(utilisateur or "") or {}
    return bool(u.get("enabled", False)) and not u.get("_fallback") and user_store.verify_password(utilisateur, mot_de_passe)


def _admin_au_mot_de_passe(utilisateur: str, mot_de_passe: str) -> bool:
    from secubox_core import second_facteur, user_store  # noqa: PLC0415
    return second_facteur.compte_admin_actif(utilisateur) and user_store.verify_password(utilisateur, mot_de_passe)


@public.post("/compte/preparer")
def compte_preparer(c: Compte, request: Request):
    _hors_relais(request)
    cle = "compte:" + c.utilisateur
    _limite(cle)
    if not _admin_au_mot_de_passe(c.utilisateur, c.mot_de_passe):
        _echecs[cle].append(time.monotonic())
        COFFRE.journal.ajouter("compte_refuse", qui=c.utilisateur)
        raise HTTPException(403, "refusé")
    return {"ticket": _appel(COFFRE.compte_preparer, c.utilisateur, c.mot_de_passe,
                             _personne_de_compte(c.utilisateur))}


@public.post("/personne/preparer")
def personne_preparer(c: Compte, request: Request):
    """Connexion d'un utilisateur ORDINAIRE ou invité avec compte (#1855) : son
    compartiment s'ouvre, jamais la clé maîtresse. Même ticket, même confirmation
    (second facteur) que l'administrateur."""
    _hors_relais(request)
    cle = "compte:" + c.utilisateur
    _limite(cle)
    if not _compte_au_mot_de_passe(c.utilisateur, c.mot_de_passe):
        _echecs[cle].append(time.monotonic())
        COFFRE.journal.ajouter("compte_refuse", qui=c.utilisateur)
        raise HTTPException(403, "refusé")
    personne = _personne_de_compte(c.utilisateur)
    if not personne:
        return {"ticket": None}
    return {"ticket": _appel(COFFRE.personne_compte_preparer, personne, c.utilisateur, c.mot_de_passe)}


@public.post("/compte/confirmer")
def compte_confirmer(t: Ticket, request: Request):
    _hors_relais(request)
    etait_ouvert = COFFRE.ouvert
    ok = COFFRE.compte_confirmer(t.ticket, origine="connexion distante" if t.distante else "connexion lan")
    if ok and t.distante and not etait_ouvert and COFFRE.ouvert:
        threading.Thread(target=_alerte_distante, args=("connexion",), daemon=True).start()
    return {"ouvert": ok}


@public.post("/compte/changer")
def compte_changer(c: Changement, request: Request):
    """Appelé APRÈS le changement : le nouveau mot de passe est déjà le bon."""
    _hors_relais(request)
    cle = "compte:" + c.utilisateur
    _limite(cle)
    if not _admin_au_mot_de_passe(c.utilisateur, c.nouveau):
        _echecs[cle].append(time.monotonic())
        raise HTTPException(403, "refusé")
    return {"renouvelee": COFFRE.compte_changer(c.utilisateur, c.ancien, c.nouveau)}


@public.post("/personne/changer")
def personne_changer(c: Changement, request: Request):
    """Même appel, pour la serrure « compte » de la personne : le nouveau mot de
    passe est déjà le bon, c'est l'ancien qui déballe la clé."""
    _hors_relais(request)
    cle = "compte:" + c.utilisateur
    _limite(cle)
    if not _compte_au_mot_de_passe(c.utilisateur, c.nouveau):
        _echecs[cle].append(time.monotonic())
        raise HTTPException(403, "refusé")
    personne = _personne_de_compte(c.utilisateur)
    return {"renouvelee": bool(personne and COFFRE.personne_compte_changer(personne, c.ancien, c.nouveau))}


# ── racine : coffrectl, pour root ─────────────────────────────────────────────
racine = FastAPI(title="SecuBox Coffre (racine)", version=VERSION, docs_url=None, redoc_url=None,
                 openapi_url=None)
_routes_communes(racine, [])


@racine.post("/initialiser")
def initialiser(p: Phrase):
    return {"codes": _appel(COFFRE.initialiser, p.phrase)}


@racine.post("/ouvrir")
def ouvrir_racine(o: Ouverture):
    if not _appel(COFFRE.ouvrir, o.secret, o.genre, qui="root", origine="console"):
        raise HTTPException(403, "refusé")
    return COFFRE.etat()


@racine.get("/secrets/{compartiment}/{nom}/valeur")
def lire(compartiment: str, nom: str):
    return {"valeur": _appel(COFFRE.lire, compartiment, nom).decode("utf-8", "replace")}


@racine.post("/serrures/phrase")
def serrure_phrase(p: Phrase):
    return {"id": _appel(COFFRE.ajouter_serrure_phrase, p.phrase, p.libelle)}


@racine.delete("/serrures/{ident}")
def serrure_retirer(ident: str):
    _appel(COFFRE.retirer_serrure, ident)
    return {"retiree": True}


@racine.post("/serrures/secours")
def codes():
    return {"codes": _appel(COFFRE.regenerer_codes)}


# Recouvrement par le maillage (P8) : root seulement — les parts ne passent
# jamais par une session web.
@racine.post("/recouvrement/preparer")
def recouvrement_preparer(d: Detenteurs):
    return _appel(COFFRE.recouvrement_preparer, d.detenteurs)


@racine.get("/recouvrement")
def recouvrement_etat():
    return {"recouvrement": COFFRE.recouvrement_etat()}


@racine.delete("/recouvrement")
def recouvrement_annuler():
    _appel(COFFRE.recouvrement_annuler)
    return {"annule": True}


@racine.post("/recouvrement/ouvrir")
def recouvrement_ouvrir(p: Parts):
    if not _appel(COFFRE.ouvrir_par_maillage, p.parts, qui="root", origine="console"):
        raise HTTPException(403, "refusé — deux parts d'un même jeu sont nécessaires")
    return COFFRE.etat()


@racine.post("/compartiments")
def compartiment(c: Compartiment):
    _appel(COFFRE.creer_compartiment, c.id, c.libelle)
    return {"cree": True}


# Compatibilité : `api.main:app` désigne la face publique.
app = public
