# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""Geste `garde-ban` (#3794) : `POST /garde/ban`, le ban posé par secubox-garde (détecteur d'intrusion de la box).

Sur le patron de `gestes_ia` (#3716), dont il reprend la garde de processus, la validation P11, le lancement de
`wafctl` et le retour arrière : exception écrite à RULES-CODE § 3, garde `require_garde` (compte de service `garde`,
portée `garde-ban`, jeton EdDSA par requête, `jti` unique, corps haché, 60 s au plus). La clé PRIVÉE est
`/etc/secubox/secrets/garde-ban.pem`, posée par `wafctl cle-garde-ban generer` (root:secubox-garde 0640) ; la clé
publique dans `/etc/secubox-comptes-service/garde/`.

Bornes, toutes vérifiées ICI :

- corps `{"geste": "ban", "cible", "duree_s", "motif"}`, champs en trop refusés, `duree_s` entier strict de 1 h à
  30 j (422 sinon) ;
- cible : UNE adresse publique, IPv4 ou IPv6, sous forme canonique. Jamais un bloc, ni le privé, l'ULA, le lien-local,
  le bouclage, la multidiffusion, le CGNAT (qui contient aussi le maillage 10.100.0.0/16 via 10.0.0.0/8), ni une
  IPv6 qui porte de l'IPv4 : 409 `forme` ou `privee` (le relais de la garde lit `motif`) ;
- déjà bannie par la garde (journal) ou déjà présente dans l'ensemble nft VIVANT (`waf_ban` / `waf_ban6`, lu avant
  wafctl) : 409 `deja_actif`, sans wafctl ni place de plafond ; ensemble illisible : 503 `etat`. Un ban étranger
  (sbxwaf, administrateur, ai-ban) n'est donc jamais touché, et le retour arrière ne retire que ce que CE geste a posé ; plafonds glissants 120/h et 1000/j : 409 `plafond` ;
- les gardes root de `wafctl ban` (`waf-blocs verifier` : plages protégées, box, pairs) : leur motif en 409.

Application par le MÊME chemin que l'ai-ban : `sudo -n wafctl ban <ip> <durée>s`, qui pose l'adresse dans `waf_ban`
ou `waf_ban6` avec timeout. (Ni `wafctl ban` ni l'ai-ban n'écrivent `bans.jsonl`, journal propre à sbxwaf : le
journal de ce geste est `JOURNAL_GARDE`.) Audit : `garde-ban-demande` avant wafctl, `garde-ban` après ; un ban dont le
journal ou l'audit échoue est retiré. Réponses : 200 `{id, cible, fin, audit}`, 409/5xx `{"detail": {"motif"}}`.
"""
from __future__ import annotations

import ipaddress
import json
import logging
import os
import re
import secrets
import threading
from pathlib import Path
from typing import Any, Callable, Dict, List, Literal

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

from secubox_core.compte_service import TAILLE_MAX_CORPS, require_garde

try:
    from api import gestes_ia as _g
except ImportError:  # pragma: no cover — import hors paquet
    import gestes_ia as _g

log = logging.getLogger("secubox.waf.garde_ban")

router = APIRouter(prefix="/garde", dependencies=[Depends(_g.processus_designe)])

#: Journal des gestes de la garde (ajout seul) : `ban` et `annule`. Il fait foi pour les plafonds.
JOURNAL_GARDE = Path("/var/lib/secubox/waf/garde-ban.jsonl")
DUREE_MIN_S, DUREE_MAX_S = 3600, 2_592_000
HEURE, JOUR = 3600, 86_400
PLAFONDS = {"heure": 120, "jour": 1000}

#: IPv6 jamais bannie par la garde, en plus de `not is_global` (ULA, lien-local, bouclage, documentation…).
_V6_INTERDITS = tuple(ipaddress.IPv6Network(r) for r in ("ff00::/8", "64:ff9b::/96", "2002::/16", "2001::/32"))
_RE_ID = re.compile(r"[0-9a-f]{32}")

_config: Dict[str, Callable[..., Any]] = {}
_verrou = threading.Lock()


def configurer(audit: Callable[[str, str, dict], None]) -> None:
    """`audit(action, detail, user)` : une ligne d'`audit.log`, qui LÈVE si elle n'a pas pu être écrite."""
    _config["audit"] = audit


class GesteGardeBan(BaseModel):
    model_config = {"extra": "forbid"}

    geste: Literal["ban"]
    cible: str = Field(max_length=45)
    duree_s: int = Field(ge=DUREE_MIN_S, le=DUREE_MAX_S, strict=True)
    motif: str = Field("", max_length=200)


def adresse_publique(texte: str) -> ipaddress._BaseAddress:
    """Une adresse IPv4 ou IPv6 publique, canonique. Lève ValueError(« forme » | « privee »)."""
    if "/" in texte:
        raise ValueError("forme")
    try:
        a = ipaddress.ip_address(texte)
    except ValueError:
        raise ValueError("forme") from None
    if str(a) != texte:
        raise ValueError("forme")
    if a.version == 4:
        # Même liste que l'ai-ban : les plages de DOCUMENTATION restent bannissables (banc et essais).
        if any(a in r for r in _g.NON_GLOBALES):
            raise ValueError("privee")
        return a
    if (not a.is_global or a.is_multicast or a.ipv4_mapped is not None or a.sixtofour is not None
            or a.teredo is not None or any(a in r for r in _V6_INTERDITS)):
        raise ValueError("privee")
    return a


async def _corps(request: Request, _user: dict = Depends(require_garde)) -> bytes:
    """Le corps brut, APRÈS la garde (qui l'a lu, borné et mis en cache) : P11."""
    corps = await request.body()
    if len(corps) > TAILLE_MAX_CORPS:
        raise HTTPException(413, detail={"motif": "corps_trop_grand"})
    return corps


def _entree_valide(e: Any) -> bool:
    if not isinstance(e, dict) or e.get("type") not in ("ban", "annule"):
        return False
    if not isinstance(e.get("id"), str) or not _RE_ID.fullmatch(e["id"]) or not _g._entier(e.get("at")):
        return False
    return e["type"] == "annule" or (isinstance(e.get("cible"), str) and _g._entier(e.get("fin")))


def _lire_journal() -> List[dict]:
    """Entrées valides de la fin du journal ; [] s'il n'existe pas. Lève OSError s'il est illisible."""
    return [e for e in (_g._lire_fin_jsonl(JOURNAL_GARDE, _g._TAILLE_LECTURE) or []) if _entree_valide(e)]


def _ecrire_journal(entree: dict) -> None:
    """Une ligne ajoutée et synchronisée, jamais à travers un lien. Lève OSError."""
    ligne = (json.dumps(entree, ensure_ascii=False) + "\n").encode("utf-8")
    fd = os.open(JOURNAL_GARDE, os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o660)
    try:
        st = os.fstat(fd)
        if st.st_uid == os.geteuid() and st.st_mode & 0o060 != 0o060:
            os.fchmod(fd, 0o660)        # même raison que gestes_ia : chown -R secubox-waf au démarrage du WAF
        os.write(fd, ligne)
        os.fsync(fd)
    finally:
        os.close(fd)


def _bilan(entrees: List[dict], maintenant: int):
    """(cibles actives, bans de la dernière heure, du dernier jour). Un ban annulé reste compté ; un ban daté du futur
    compte pour un âge nul."""
    bans: Dict[str, dict] = {}
    annules = set()
    for e in entrees:
        if e["type"] == "ban":
            bans.setdefault(e["id"], e)
        else:
            annules.add(e["id"])
    actives = {b["cible"] for i, b in bans.items() if i not in annules and b["fin"] > maintenant}
    heure = jour = 0
    for b in bans.values():
        age = max(0, maintenant - b["at"])
        if age < JOUR:
            jour += 1
            heure += age < HEURE
    return actives, heure, jour


def _lire_ensemble(nom: str):
    """Adresses de l'ensemble nft vivant `nom` ; lève si illisible (`gestes_ia.lire_waf_ban`)."""
    return _g.lire_waf_ban(nom)


def _auditer(action: str, detail: str, user: dict) -> None:
    """Lève si la ligne n'a pas pu être écrite. Empreinte de la clé ajoutée, jamais le jeton."""
    _config["audit"](action, f"{detail} cle {_g._cle(user)}", {"sub": str((user or {}).get("sub") or "garde")})


def _refus(statut: int, motif: str, cible: str, user: dict) -> HTTPException:
    action = "garde-ban-refus" if statut == 409 else "garde-ban-echec"
    _g._auditer_regroupe(action, motif, "garde", f"motif {motif} cible {cible[:45]}",
                         {"sub": str((user or {}).get("sub") or "garde"), "cle": _g._cle(user)})
    return HTTPException(statut, detail={"motif": motif})


@router.post("/ban")
def garde_ban(user: dict = Depends(require_garde), corps: bytes = Depends(_corps)) -> Dict[str, Any]:
    geste: GesteGardeBan = _g._valider(GesteGardeBan, corps)
    try:
        cible = adresse_publique(geste.cible)
    except ValueError as e:
        raise _refus(409, str(e), geste.cible, user) from None
    with _verrou:
        maintenant = int(_g._maintenant())
        try:
            actives, heure, jour = _bilan(_lire_journal(), maintenant)
        except OSError:
            raise _refus(503, "journal", geste.cible, user) from None
        if geste.cible in actives:
            raise _refus(409, "deja_actif", geste.cible, user)
        try:
            present = str(cible) in _lire_ensemble("waf_ban6" if cible.version == 6 else "waf_ban")
        except Exception as e:  # noqa: BLE001 — ensemble illisible : jamais « libre » par défaut
            log.warning("garde-ban : ensemble illisible : %s", e)
            raise _refus(503, "etat", geste.cible, user) from None
        if present:
            raise _refus(409, "deja_actif", geste.cible, user)
        if heure >= PLAFONDS["heure"] or jour >= PLAFONDS["jour"]:
            raise _refus(409, "plafond", geste.cible, user)

        ident = secrets.token_hex(16)
        fin = maintenant + geste.duree_s
        resume = f"id {ident} cible {geste.cible} {geste.duree_s}s fin {fin}"
        try:
            _auditer("garde-ban-demande", resume, user)
        except Exception:  # noqa: BLE001 — sans trace de la demande, rien n'est fait
            raise _refus(503, "audit", geste.cible, user) from None

        r, panne = _g._lancer(_g._argv("ban", cible, geste.duree_s))
        if r is None:
            log.error("garde-ban : wafctl injoignable (%s) pour %s", panne, cible)
            _g._defaire(cible, "garde-ban")
            raise _refus(503, "wafctl", geste.cible, user)
        if r.returncode != 0:
            raise _refus(*_g._statut_motif(_g._motif_sortie(r)), geste.cible, user)

        entree = {"ts": _g._horodatage(), "at": maintenant, "type": "ban", "id": ident, "cible": geste.cible,
                  "fin": fin, "duree_s": geste.duree_s, "motif": geste.motif,
                  "jti": str((user or {}).get("jti") or ""), "cle": _g._cle(user)}
        try:
            _ecrire_journal(entree)
        except OSError:
            # hors journal, le ban échapperait aux plafonds
            if _g._defaire(cible, "garde-ban"):
                raise _refus(503, "journal", geste.cible, user) from None
            raise _refus(500, "incoherent", geste.cible, user) from None
        try:
            _auditer("garde-ban", f"{resume} motif {geste.motif}", user)
        except Exception:  # noqa: BLE001 — un ban non audité n'existe pas : il est retiré
            defait = _g._defaire(cible, "garde-ban")
            try:
                _ecrire_journal({"ts": _g._horodatage(), "at": maintenant, "type": "annule", "id": ident,
                                 "cible": geste.cible, "cause": "audit"})
            except OSError:
                log.error("garde-ban : annulation %s non journalisée", ident)
            raise HTTPException(500, detail={"motif": "audit" if defait else "incoherent"}) from None
    return {"id": ident, "cible": geste.cible, "fin": fin, "audit": ident}


# ── `POST /garde/unban` : levée d'un ban posé par la garde (page /garde/ « Débannir ») ──
PLAFOND_UNBAN_HEURE = 60


class GesteGardeUnban(BaseModel):
    model_config = {"extra": "forbid"}

    geste: Literal["unban"]
    cible: str = Field(max_length=45)


def _bans_actifs_de(entrees: List[dict], cible: str, maintenant: int) -> List[str]:
    """Ids des bans de la garde pour `cible`, non échus et non annulés."""
    annules = {e["id"] for e in entrees if e["type"] == "annule"}
    return sorted({e["id"] for e in entrees if e["type"] == "ban" and e["cible"] == cible
                   and e["fin"] > maintenant and e["id"] not in annules})


def _unbans_heure(entrees: List[dict], maintenant: int) -> int:
    return sum(1 for e in entrees if e["type"] == "annule" and e.get("geste") == "unban"
               and maintenant - e["at"] < HEURE)


@router.post("/unban")
def garde_unban(user: dict = Depends(require_garde), corps: bytes = Depends(_corps)) -> Dict[str, Any]:
    """Seulement une adresse qui a un ban de la garde actif dans garde-ban.jsonl (409 `pas_garde` sinon) : un ban
    étranger n'est jamais levé. Application par `wafctl unban` (chemin du retour arrière de l'ai-ban), journal
    `annule` + `geste: unban`, audit `garde-unban` avant le geste. Plafond propre : 60/h."""
    geste: GesteGardeUnban = _g._valider(GesteGardeUnban, corps)
    try:
        cible = adresse_publique(geste.cible)
    except ValueError:
        raise _refus(409, "pas_garde", geste.cible, user) from None
    with _verrou:
        maintenant = int(_g._maintenant())
        try:
            entrees = _lire_journal()
        except OSError:
            raise _refus(503, "journal", geste.cible, user) from None
        ids = _bans_actifs_de(entrees, geste.cible, maintenant)
        if not ids:
            raise _refus(409, "pas_garde", geste.cible, user)
        if _unbans_heure(entrees, maintenant) >= PLAFOND_UNBAN_HEURE:
            raise _refus(409, "plafond", geste.cible, user)
        resume = f"ids {','.join(ids)} cible {geste.cible}"
        try:
            _auditer("garde-unban", resume, user)
        except Exception:  # noqa: BLE001 — lever un ban sans trace serait pire que ne pas le lever
            raise _refus(503, "audit", geste.cible, user) from None
        r, _ = _g._lancer(_g._argv("unban", cible))
        if r is None or r.returncode != 0:
            statut, motif = (503, "wafctl") if r is None else _g._statut_motif(_g._motif_sortie(r))
            raise _refus(statut, motif, geste.cible, user)
        try:
            for i in ids:
                _ecrire_journal({"ts": _g._horodatage(), "at": maintenant, "type": "annule", "id": i,
                                 "cible": geste.cible, "geste": "unban", "cause": "garde"})
        except OSError:
            # levé et audité ; un nouvel essai refera un retrait idempotent puis la ligne
            raise _refus(503, "journal", geste.cible, user) from None
    return {"cible": geste.cible, "ids": ids, "etat": "annule"}
