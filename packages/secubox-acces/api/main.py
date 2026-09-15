# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: Accès — l'API (#1344).
CyberMind — https://cybermind.fr

TROIS SURFACES, ET ELLES N'ONT PAS LE MÊME PUBLIC :

  • `/invitation/*` — OUVERTE. La seule porte de SecuBox qui accepte un inconnu,
    parce qu'il faut bien un premier contact. Bornée : une demande par appareil,
    plafond par adresse, corps limité, et rien qui distingue un DID inconnu d'un
    DID refusé — sinon la route devient un moyen d'énumérer qui a accès.

  • `/session/*` — OUVERTE aussi, mais elle exige une PREUVE. C'est ici qu'un
    appareil admis échange sa demande contre un cookie de session, en signant
    un défi avec la clé dont l'empreinte a été validée.

  • `/file/*` et `/profils/*` — ADMIN. Trancher, promouvoir, révoquer.
"""
from __future__ import annotations

import io
import logging
import time
from pathlib import Path
from typing import Optional

from fastapi import Depends, FastAPI, HTTPException, Request, Response
from pydantic import BaseModel, Field

from secubox_core.auth import create_token, require_jwt, set_session_cookie

from .identite import verifie_signature
from .profileur import PROFILS, DemandeInvalide, Profileur
from .session import Portier, SessionRefusee

log = logging.getLogger("secubox.acces")

app = FastAPI(title="SecuBox Accès", version="1.0.0")

FICHIER = Path("/var/lib/secubox/acces/demandes.json")
CONF = Path("/etc/secubox/acces.toml")

#: Plafond par adresse. Volontairement bas : une demande d'accès est un geste
#: humain, pas une boucle. Cinq essais laissent de la place aux hésitations sans
#: ouvrir la porte à un remplissage.
PLAFOND_PAR_IP = 5
FENETRE_S = 3600

#: La page qui porte le formulaire, quand personne ne dit où elle est.
#:
#: ELLE N'EST PAS AU MÊME ENDROIT SELON LE VHOST : à la racine sur le vhost
#: dédié, sous /acces/ quand le module est monté dans un vhost partagé. Deviner
#: (« si l'hôte commence par acces. alors… ») marcherait jusqu'au jour où l'on
#: renommerait le vhost. C'est donc nginx qui le DIT, par un en-tête, et cette
#: valeur n'est que le repli.
PAGE_INVITATION = "/acces/"


def _page(req: Request) -> str:
    """Le chemin de la page d'invitation sur CE vhost."""
    r = (req.headers.get("x-acces-racine") or "").strip()
    # On n'accepte qu'un chemin absolu : un en-tête forgé ne doit pas pouvoir
    # faire encoder une URL vers un autre site dans notre QR.
    if r.startswith("/") and "//" not in r and "\\" not in r:
        return r
    return PAGE_INVITATION


def _porte_publique() -> str:
    """L'adresse que l'on DONNE à quelqu'un. Vide si l'opérateur n'en a pas fixé.

    LE QR DOIT TOUJOURS DÉSIGNER LA PORTE PUBLIQUE, pas le vhost que
    l'administrateur regarde au moment où il le montre. Déduire l'URL de la
    requête avait deux défauts, et le second est le vrai :

      • l'agrégateur MONTE ce module en processus pour les vhosts partagés, et
        son appel interne ne porte qu'un `Host: localhost` — l'URL déduite ne
        menait alors nulle part ;

      • surtout, un administrateur qui regarde la carlette depuis admin.gk2
        aurait distribué une adresse d'ADMIN à un inconnu. C'est précisément la
        faute que ce module existe pour corriger : le demandeur n'a pas à
        connaître le panneau d'administration, ni à l'atteindre.
    """
    # ON LIT NOTRE PROPRE FICHIER, pas `get_config()` : celui-ci ne charge
    # qu'un seul document (`secubox.conf`) et ignore les TOML par module. Un
    # `get_config("acces")` rendait donc silencieusement une section vide —
    # et le repli déduisait alors une URL depuis un `Host: localhost`.
    try:
        import tomllib
        with open(CONF, "rb") as f:
            u = str(tomllib.load(f).get("acces", {}).get("url_publique", "") or "").strip()
    except (OSError, ValueError, KeyError):
        u = ""
    if not (u.startswith("https://") or u.startswith("http://")):
        return ""
    return u.rstrip("/") + "/"

_profileur: Optional[Profileur] = None
_portier: Optional[Portier] = None
_compteur: dict[str, list[float]] = {}


def profileur() -> Profileur:
    global _profileur
    if _profileur is None:
        _profileur = Profileur(FICHIER)
    return _profileur


def portier() -> Portier:
    global _portier
    if _portier is None:
        _portier = Portier(profileur(), verifie_signature)
    return _portier


def _ip(req: Request) -> str:
    return ((req.headers.get("x-forwarded-for", "").split(",")[0].strip())
            or (req.client.host if req.client else "?"))


def _cadence(req: Request) -> None:
    """Plafonne les demandes par adresse. Lève 429 au-delà."""
    ip = _ip(req)
    maintenant = time.monotonic()
    essais = [t for t in _compteur.get(ip, []) if maintenant - t < FENETRE_S]
    if len(essais) >= PLAFOND_PAR_IP:
        raise HTTPException(429, "Trop de demandes. Réessayez plus tard.")
    essais.append(maintenant)
    _compteur[ip] = essais


def _qui(req: Request) -> str:
    u = getattr(req.state, "user", None)
    return str(getattr(u, "username", None) or u or "admin")


def _base_publique(req: Request) -> str:
    """L'URL publique par laquelle CETTE requête est arrivée.

    LE SCHÉMA EST DÉCIDÉ, PAS LU. `X-Forwarded-Proto` traverse deux mandataires :
    HAProxy termine le TLS et le pose à `https`, puis nginx le réécrit parfois
    avec son propre `$scheme`, qui vaut `http` puisque le TLS est déjà terminé
    en amont. Le suivre encoderait « http:// » dans le QR d'un service joignable
    en HTTPS seulement. Un nom qualifié n'est atteignable que par HAProxy, donc
    en TLS ; le clair n'est retenu que pour localhost et les accès par adresse.
    """
    hote = ((req.headers.get("x-forwarded-host") or req.headers.get("host") or "")
            .split(",")[0].strip())
    if not hote:
        return ""
    nu = hote.split(":")[0]
    clair = nu in ("localhost", "127.0.0.1", "::1") or nu.replace(".", "").isdigit()
    return f"{'http' if clair else 'https'}://{hote}"


# ─────────────────────────────────────────────────────────────────────────────
# Surface OUVERTE — la demande
# ─────────────────────────────────────────────────────────────────────────────

class DemandeIn(BaseModel):
    """Le formulaire. Inscription, invitation et demande d'accès à la fois."""
    did: str = Field(max_length=160)
    cle_publique: str = Field(max_length=200)   # point P-256 : 130 signes
    nom: str = Field(max_length=60)
    message: str = Field(default="", max_length=500)
    appareil: str = Field(default="", max_length=60)


@app.get("/health")
async def health():
    p = profileur()
    return {"status": "ok", "en_attente": len(p.en_attente()), "admis": len(p.admis())}


@app.post("/invitation/demande")
async def demander(corps: DemandeIn, req: Request):
    """Déposer une demande d'accès. **Non authentifié — c'est le but.**"""
    _cadence(req)
    try:
        d = profileur().demande(corps.model_dump())
    except DemandeInvalide as e:
        raise HTTPException(400, str(e)) from e

    if d.etat == "acceptee":
        return {"etat": "acceptee", "profil": d.profil, "empreinte": d.empreinte}

    log.info("demande d'accès : %s (%s) — empreinte %s", d.nom, d.appareil, d.empreinte)
    return {
        # Le jeton de suivi n'est rendu QU'ICI, une fois : c'est avec lui que
        # l'appareil sondera, puis réclamera sa session.
        "etat": d.etat, "jeton": d.jeton, "empreinte": d.empreinte,
    }


@app.get("/invitation/suivi")
async def suivi(did: str, jeton: str):
    """Où en est MA demande. Non authentifié, mais il faut le jeton."""
    vue = profileur().suivi(did, jeton)
    if vue is None:
        # MÊME RÉPONSE pour « inconnu » et « mauvais jeton » : les distinguer
        # ferait de cette route un moyen de savoir quels appareils ont demandé.
        raise HTTPException(404, "Demande introuvable.")
    return vue


def _url_invitation(req: Request) -> str:
    """L'adresse du formulaire : la porte publique si elle est fixée, sinon
    celle par laquelle cette requête est arrivée."""
    porte = _porte_publique()
    if porte:
        return porte
    base = _base_publique(req)
    if not base:
        raise HTTPException(400, "hôte indéterminable")
    return base + _page(req)


def _url_sbxos() -> str:
    """Où vit SBX OS. C'EST LE SERVEUR QUI LE DIT, et pas le client.

    La carlette est servie depuis le vhost d'accès mais EMBARQUÉE dans le Hall :
    un chemin relatif comme « /sbxos/ » désignerait donc tantôt le vhost
    d'accès, tantôt celui du Hall, selon qui l'interprète — et ne mènerait nulle
    part dans les deux cas. Une adresse absolue, décidée par l'opérateur, ne
    souffre pas de cette ambiguïté.
    """
    try:
        import tomllib
        with open(CONF, "rb") as f:
            u = str(tomllib.load(f).get("acces", {}).get("url_sbxos", "") or "").strip()
    except (OSError, ValueError, KeyError):
        u = ""
    return u if u.startswith("http") else "/sbxos/"


@app.get("/invitation/url")
async def invitation_url(req: Request):
    return {"url": _url_invitation(req), "qr": "/api/v1/acces/invitation/qr",
            "sbxos": _url_sbxos()}


@app.get("/invitation/qr")
async def invitation_qr(req: Request):
    """Le QR de l'URL d'invitation. **Sans secret.**

    UN QR D'URL EST UN CONFORT ; UN QR DE SECRET EST UN CANAL. Celui-ci n'encode
    que l'adresse publique du formulaire. L'EMPREINTE, elle, n'est jamais mise
    en QR : la comparer d'un regard EST le geste qui vérifie qu'on valide le bon
    appareil, et un QR scanné à sa place supprimerait la vérification en croyant
    l'automatiser.
    """
    url = _url_invitation(req)
    try:
        import qrcode
    except ImportError:  # pragma: no cover
        raise HTTPException(503, "génération de QR indisponible") from None

    q = qrcode.QRCode(error_correction=qrcode.constants.ERROR_CORRECT_M,
                      box_size=6, border=2)
    q.add_data(url)
    q.make(fit=True)
    tampon = io.BytesIO()
    q.make_image(fill_color="black", back_color="white").save(tampon, format="PNG")
    return Response(
        content=tampon.getvalue(), media_type="image/png",
        headers={
            # Le QR dépend de l'hôte demandé : un cache partagé qui l'ignorerait
            # servirait à l'un le QR de l'autre.
            "Vary": "X-Forwarded-Host, Host",
            "Cache-Control": "public, max-age=300",
            "X-Invitation-URL": url,
        },
    )


# ─────────────────────────────────────────────────────────────────────────────
# Surface OUVERTE — la session, contre PREUVE
# ─────────────────────────────────────────────────────────────────────────────

class OuvertureIn(BaseModel):
    did: str = Field(max_length=160)
    jeton: str = Field(max_length=64)
    defi: str = Field(max_length=64)
    signature: str = Field(max_length=200)


@app.get("/session/defi")
async def session_defi(did: str, jeton: str, req: Request):
    """Un défi à signer. Usage unique, lié au DID, périmé en deux minutes."""
    _cadence(req)
    try:
        return {"defi": portier().defi(did, jeton)}
    except SessionRefusee as e:
        raise HTTPException(403, str(e)) from e


@app.post("/session/ouvrir")
async def session_ouvrir(corps: OuvertureIn, reponse: Response):
    """Échanger une preuve contre une session.

    C'EST LE CHAÎNON QUI MANQUAIT. Avant, l'appareil lisait « Accès accordé » et
    le Hall continuait de le voir comme un visiteur : la file savait dire oui,
    personne n'ouvrait la porte.
    """
    try:
        d = portier().ouvre(corps.did, corps.jeton, corps.defi, corps.signature)
    except SessionRefusee as e:
        raise HTTPException(403, str(e)) from e

    # Le jeton porte le NOM déclaré à l'admission, pas le DID : c'est ce que
    # l'administrateur a vu et validé, et c'est ce qui s'affichera partout.
    jwt = create_token(d["nom"], expires_in=d["duree"])
    set_session_cookie(reponse, jwt, expires_in=d["duree"])
    profileur().note_session(corps.did)
    log.info("session ouverte pour %s (%s), profil %s", d["nom"], corps.did, d["profil"])
    return {"ok": True, "nom": d["nom"], "profil": d["profil"]}


# ─────────────────────────────────────────────────────────────────────────────
# Surface ADMIN — la file et les profils
# ─────────────────────────────────────────────────────────────────────────────

class Verdict(BaseModel):
    did: str
    motif: str = Field(default="", max_length=200)
    #: Lu par /profils/promouvoir UNIQUEMENT. L'admission l'ignore : elle n'a
    #: qu'une issue, `guest`.
    profil: str = "guest"


@app.get("/file", dependencies=[Depends(require_jwt)])
async def file_attente():
    """Les demandes à trancher, avec leur empreinte."""
    return {"en_attente": profileur().en_attente()}


@app.get("/profils", dependencies=[Depends(require_jwt)])
async def profils():
    """Les accès accordés — la matière du profileur.

    On ne promeut pas une demande, on promeut un ACCÈS. Séparer les deux listes
    est ce qui rend l'écran lisible : à gauche ce qui attend une décision, à
    droite ce qui vit déjà.
    """
    return {"admis": profileur().admis(), "profils": list(PROFILS)}


@app.post("/file/accepter", dependencies=[Depends(require_jwt)])
async def accepter(v: Verdict, req: Request):
    """Admettre un appareil. **L'issue est toujours `guest`.**

    Le champ `profil` du corps est IGNORÉ, délibérément : une admission ouvre
    une session, elle ne crée pas un utilisateur.
    """
    try:
        d = profileur().accepte(v.did, par=_qui(req))
    except DemandeInvalide as e:
        raise HTTPException(400, str(e)) from e
    return {"ok": True, "did": d.did, "profil": d.profil}


@app.post("/file/refuser", dependencies=[Depends(require_jwt)])
async def refuser(v: Verdict, req: Request):
    try:
        d = profileur().refuse(v.did, par=_qui(req), motif=v.motif)
    except DemandeInvalide as e:
        raise HTTPException(400, str(e)) from e
    return {"ok": True, "did": d.did}


@app.post("/profils/promouvoir", dependencies=[Depends(require_jwt)])
async def promouvoir(v: Verdict, req: Request):
    """Changer le profil d'un admis. C'est ICI, et nulle part ailleurs, que
    `admin` devient possible."""
    if v.profil not in PROFILS:
        raise HTTPException(400, f"profil inconnu : {v.profil}")
    try:
        d = profileur().promeut(v.did, vers=v.profil, par=_qui(req))
    except DemandeInvalide as e:
        raise HTTPException(400, str(e)) from e
    log.info("profil de %s porté à %s par %s", d.did, d.profil, d.traitee_par)
    return {"ok": True, "did": d.did, "profil": d.profil}


@app.post("/profils/revoquer", dependencies=[Depends(require_jwt)])
async def revoquer(v: Verdict, req: Request):
    try:
        d = profileur().revoque(v.did, par=_qui(req))
    except DemandeInvalide as e:
        raise HTTPException(400, str(e)) from e
    return {"ok": True, "did": d.did}
