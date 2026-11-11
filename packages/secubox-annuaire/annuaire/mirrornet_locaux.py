# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Indices TV Privacy (#3666) : offre, versions et abonnements « tv-indices » signés EN TÂCHE DE FOND.

secubox-mirrornet (compte dédié, sans accès à `node.key`) tire l'objet de la publication d'ad-guard, le garde dans son
dépôt, puis écrit `publications.json` :

    {"format": 1, "jeux": {"tv-indices": {"publier": bool, "recevoir": bool, "empreinte": "b2:<64 hex>"|null,
                                          "taille": int|null}}}

L'annuaire (compte `secubox`, seul détenteur de la clé) le lit après chaque passe de synchronisation et signe, comme
`offres.py` (#3021) le fait pour les services réels — mais rien d'autre que :
  · SON offre `kind=dataset`, `scope.usage = tv-indices` (créée au premier besoin, retirée quand `publier` est faux) ;
  · une version de cette offre (manifeste seulement : l'objet est déjà dans le dépôt de MirrorNet), au plus une par
    heure et seulement quand l'empreinte change ;
  · un abonnement à l'offre `tv-indices` de chaque AUTRE nœud de niveau ≥ LIMITED (jamais OBSERVER ni REVOKED), lié à
    son fournisseur ; ou, `recevoir` faux, la résiliation de ces abonnements.
Une demande absente, illisible ou invalide, ou une clé absente : aucun geste. Deux passes de suite avec la même demande :
la seconde ne signe rien. Le propriétaire garde la main : un abonnement qu'il a résilié lui-même, ou que le fournisseur
a refusé ou révoqué, n'est jamais repris par la tâche de fond.
"""
from __future__ import annotations

import json
import logging
import os
import re
import stat
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

# Surchargeable pour les tests (variable d'environnement, comme les autres chemins de l'annuaire).
PUBLICATIONS = Path(os.environ.get("ANNUAIRE_MIRRORNET_PUBLICATIONS",
                                   "/var/lib/secubox-mirrornet-partage/publications.json"))
USAGE = "tv-indices"
TAILLE_MAX = 64 * 1024                    # publications.json : quelques centaines d'octets en pratique
OBJET_MAX = 2 * 1024 * 1024               # même plafond que MirrorNet (TAILLE_MAX de locaux.py)
INTERVALLE = timedelta(seconds=3600)      # une version au plus par heure
NIVEAUX_ECOUTES = ("LIMITED", "PARTNER", "TRUSTED")
# Motif signé des résiliations de la tâche de fond : les distingue d'une résiliation du propriétaire (respectée).
MOTIF_FOND = "réception des indices TV coupée (tâche de fond)"

OFFRE = {"kind": "dataset", "approval_mode": "auto", "classe": "communaute", "scope": {"usage": USAGE},
         "description": "Domaines publicité, pistage et télémétrie confirmés par TV Privacy, et domaines légitimes "
                        "(domaine → catégorie, rien d'autre)."}
MANIFESTE = {"classe": "communaute", "format": "application/json", "licence": "CC0-1.0",
             "provenance": "secubox-ad-guard:tv-indices", "donnees_personnelles": "non"}

_EMPREINTE = re.compile(r"^b2:[0-9a-f]{64}\Z")
_log = logging.getLogger("secubox.annuaire.sync")


# --- demande ------------------------------------------------------------------------------------------------------

def valider(jeu: Any) -> Optional[Dict[str, Any]]:
    """Demande `tv-indices` bien formée, recopiée champ à champ ; None sinon (jamais d'exception)."""
    if not isinstance(jeu, dict):
        return None
    publier, recevoir, empreinte, taille = (jeu.get(k) for k in ("publier", "recevoir", "empreinte", "taille"))
    if type(publier) is not bool or type(recevoir) is not bool:
        return None
    if empreinte is None and taille is None:
        return {"publier": publier, "recevoir": recevoir, "empreinte": None, "taille": None}
    if not (isinstance(empreinte, str) and _EMPREINTE.match(empreinte)
            and type(taille) is int and 0 <= taille <= OBJET_MAX):
        return None
    return {"publier": publier, "recevoir": recevoir, "empreinte": empreinte, "taille": taille}


def lire_demandes(chemin: Optional[Path] = None) -> Optional[Dict[str, Any]]:
    """La demande `tv-indices` de `publications.json` : fichier ORDINAIRE (jamais un lien), ≤ 64 Kio, JSON strict.
    Absent, illisible ou invalide : None (aucun geste)."""
    chemin = Path(chemin) if chemin is not None else PUBLICATIONS
    fd = -1
    try:
        fd = os.open(str(chemin), os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_NONBLOCK", 0))
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_size > TAILLE_MAX:
            return None
        with os.fdopen(fd, "rb") as f:
            fd = -1
            brut = f.read(TAILLE_MAX + 1)
        if len(brut) > TAILLE_MAX:
            return None
        d = json.loads(brut.decode("utf-8"))
    except (OSError, ValueError, UnicodeDecodeError, RecursionError):
        return None
    finally:
        if fd >= 0:
            os.close(fd)
    if not isinstance(d, dict) or d.get("format") != 1 or not isinstance(d.get("jeux"), dict):
        return None
    return valider(d["jeux"].get(USAGE))


# --- lecture du journal -------------------------------------------------------------------------------------------

def _est_tv(o: Dict[str, Any]) -> bool:
    scope = o.get("scope")
    return o.get("kind") == "dataset" and isinstance(scope, dict) and scope.get("usage") == USAGE


def _toutes_offres(journal) -> Dict[str, Dict[str, Any]]:
    """service_id → dernière offre auto-signée de son PREMIER fournisseur, retirée ou non (un seul balayage)."""
    from annuaire.model import Op  # noqa: PLC0415
    offres: Dict[str, Dict[str, Any]] = {}
    proprio: Dict[str, str] = {}
    for e in journal.iter_entries(ops=(Op.SERVICE_OFFER.value,)):
        p = e.payload
        sid, prov = p.get("service_id"), p.get("provider")
        if e.op != Op.SERVICE_OFFER or not sid or not prov or e.author != prov:
            continue
        if proprio.setdefault(sid, prov) == prov:
            offres[sid] = p
    return offres


def abonnements_en_cours(journal, abonne: str, maintenant: Optional[datetime] = None) -> Dict[str, List[str]]:
    """service_id → abonnements de `abonne` encore en cours (en attente ou approuvés, non échus), dans l'ordre du
    journal. Même règle que `_abonnement_en_cours` de l'API (qui s'appuie sur celle-ci)."""
    from annuaire.model import Op, SubscriptionState  # noqa: PLC0415
    from annuaire.verbs import _instant, echeance_abonnement, subscription_state  # noqa: PLC0415
    maintenant = maintenant or datetime.now(timezone.utc)
    res: Dict[str, List[str]] = {}
    for e in journal.iter_entries(ops=(Op.SERVICE_SUBSCRIBE.value,)):
        p = e.payload
        if e.op != Op.SERVICE_SUBSCRIBE or e.author != abonne or p.get("subscriber") != abonne:
            continue
        sub_id = p.get("subscription_id")
        if subscription_state(journal, sub_id) not in (SubscriptionState.PENDING, SubscriptionState.APPROVED):
            continue
        ech = _instant(echeance_abonnement(journal, sub_id, maintenant))
        if ech is None or ech > maintenant:
            res.setdefault(p.get("service_id"), []).append(sub_id)
    return res


def _refus(journal, did: str, offres: Dict[str, Dict[str, Any]]) -> set:
    """service_id dont le DERNIER abonnement de ce nœud a été clos par le propriétaire (résiliation sans le motif de
    fond) ou par le fournisseur (refus, révocation) : la tâche de fond ne s'y réabonne pas."""
    from annuaire.model import Op  # noqa: PLC0415
    from annuaire.verbs import forme_valide  # noqa: PLC0415
    dernier: Dict[str, str] = {}                         # service_id → dernier subscription_id de ce nœud
    clos: Dict[str, bool] = {}                           # subscription_id → clos par le propriétaire ou le fournisseur
    sub_vers_sid: Dict[str, str] = {}
    for e in journal.iter_entries(ops=("service_",)):
        p = e.payload
        if e.op == Op.SERVICE_SUBSCRIBE:
            if e.author == did and p.get("subscriber") == did and p.get("subscription_id"):
                dernier[p.get("service_id")] = p["subscription_id"]
                sub_vers_sid[p["subscription_id"]] = p.get("service_id")
            continue
        sub_id = p.get("subscription_id")
        if sub_id not in sub_vers_sid or not forme_valide(e.op, p, e.author):
            continue
        fournisseur = (offres.get(sub_vers_sid[sub_id]) or {}).get("provider")
        if e.op == Op.SERVICE_REVOKE_SUB and e.author == did:
            clos[sub_id] = p.get("motif") != MOTIF_FOND
        elif e.op in (Op.SERVICE_REVOKE_OFFER_SUB, Op.SERVICE_REJECT) and fournisseur and e.author == fournisseur:
            clos[sub_id] = True
    return {sid for sid, sub_id in dernier.items() if clos.get(sub_id)}


def _nom(boxname: Any, did: str) -> str:
    nom = "".join(c for c in boxname if c.isprintable()).strip()[:48] if isinstance(boxname, str) else ""
    return f"Indices TV Privacy — {nom or 'box-' + did[8:16]}"


# --- traitement ---------------------------------------------------------------------------------------------------

def traiter(journal, priv: Optional[bytes], did: Optional[str], boxname: str, demandes: Optional[dict],
            maintenant: datetime, *, auditer: Optional[Callable[..., None]] = None) -> Dict[str, Any]:
    """Aligne le journal sur la demande. Rend {"offre": "creee"|"existante"|"retiree"|None, "version": empreinte|None,
    "abonnements": n, "resiliations": n}. `auditer(action, **détails)` est appelé après chaque geste signé.

    Aucune exception vers l'appelant pour un geste refusé (journalisé, les autres gestes continuent) ; l'appelant tient
    le verrou des abonnements (vérification « déjà en cours » puis signature, sans entrelacement)."""
    from annuaire import confiance  # noqa: PLC0415
    from annuaire.verbs import (_get_offers, cancel_subscription, dataset_versions,  # noqa: PLC0415
                                offer_service, publish_dataset_version, revoke_offer, subscribe)
    res: Dict[str, Any] = {"offre": None, "version": None, "abonnements": 0, "resiliations": 0}
    d = valider(demandes)
    if not priv or not did or d is None:
        return res
    noter = auditer or (lambda action, **details: None)

    def geste(quoi: str, fn, *args, **kwargs):
        try:
            return fn(*args, **kwargs)
        except (ValueError, PermissionError) as e:     # pydantic.ValidationError hérite de ValueError
            _log.warning("indices TV : %s refusé : %s", quoi, e)
            return None

    vivantes = _get_offers(journal)
    miennes = [o for o in vivantes if o.get("provider") == did and _est_tv(o)]

    # Publication : l'offre, puis la version.
    if d["publier"]:
        if miennes:
            sid, res["offre"] = miennes[0]["service_id"], "existante"
        else:
            nom = _nom(boxname, did)
            o = geste("offre", offer_service, journal, priv, did, name=nom, endpoint=f"mirrornet://{did}/{USAGE}",
                      **{**OFFRE, "scope": dict(OFFRE["scope"])})
            sid = o.service_id if o is not None else None
            if sid:
                res["offre"] = "creee"
                noter("mirrornet_tv_indices_offre_publiee", service_id=sid, nom=nom)
        if sid and d["empreinte"]:
            versions = dataset_versions(journal, sid)
            deja = any(v.get("empreinte") == d["empreinte"] for v in versions)     # immuable : jamais republiée
            instants = [t for t in (_instant(v.get("cree_le")) for v in versions) if t is not None]
            recente = bool(instants) and maintenant - max(instants) < INTERVALLE
            if not deja and not recente:
                v = geste("version", publish_dataset_version, journal, priv, did, sid, empreinte=d["empreinte"],
                          taille=d["taille"], **MANIFESTE)
                if v is not None:
                    res["version"] = d["empreinte"]
                    noter("mirrornet_tv_indices_version_publiee", service_id=sid, numero=v.numero,
                          empreinte=d["empreinte"], taille=d["taille"])
    else:
        for o in miennes:
            if geste("retrait de l'offre", revoke_offer, journal, priv, did, o["service_id"]) is not None:
                res["offre"] = "retiree"
                noter("mirrornet_tv_indices_offre_retiree", service_id=o["service_id"])

    # Réception : abonnements aux offres tv-indices des AUTRES nœuds, ou leur résiliation.
    en_cours = abonnements_en_cours(journal, did, maintenant)
    if d["recevoir"]:
        niveaux = confiance.niveaux(journal)
        refus = _refus(journal, did, _toutes_offres(journal))
        for o in vivantes:
            sid, prov = o.get("service_id"), o.get("provider")
            if not sid or not prov or prov == did or not _est_tv(o) or o.get("classe") == "prive":
                continue
            if niveaux.get(prov, ("OBSERVER", ""))[0] not in NIVEAUX_ECOUTES or sid in en_cours or sid in refus:
                continue
            duree = o.get("duree_s")
            expire = (maintenant + timedelta(seconds=duree)).isoformat() \
                if isinstance(duree, int) and not isinstance(duree, bool) and duree > 0 else None
            s = geste("abonnement", subscribe, journal, priv, did, sid, tarif_accepte=o.get("tarif"),
                      expire_le=expire, provider=prov)
            if s is not None:
                res["abonnements"] += 1
                noter("mirrornet_tv_indices_abonnement", subscription_id=s.subscription_id, service_id=sid,
                      fournisseur=prov)
    else:
        toutes = _toutes_offres(journal)
        for sid, subs in en_cours.items():
            o = toutes.get(sid)
            if o is None or o.get("provider") == did or not _est_tv(o):
                continue
            for sub_id in subs:
                if geste("résiliation", cancel_subscription, journal, priv, did, sub_id, MOTIF_FOND) is not None:
                    res["resiliations"] += 1
                    noter("mirrornet_tv_indices_resiliation", subscription_id=sub_id, service_id=sid,
                          fournisseur=o.get("provider"))
    return res


def _instant(ts: Any) -> Optional[datetime]:
    from annuaire.verbs import _instant as instant  # noqa: PLC0415
    return instant(ts)
