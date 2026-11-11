# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Indices TV Privacy (#3666) : offre, versions et abonnements « tv-indices » signés EN TÂCHE DE FOND.

secubox-mirrornet (compte dédié, sans accès à `node.key`) tire l'objet de la publication d'ad-guard, le garde dans son
dépôt, puis écrit `publications.json` :

    {"format": 1, "confiance_min": "LIMITED"|"PARTNER"|"TRUSTED",
     "jeux": {"tv-indices": {"publier": bool, "recevoir": bool, "empreinte": "b2:<64 hex>"|null, "taille": int|null}}}

L'annuaire (compte `secubox`, seul détenteur de la clé) le lit après chaque passe de synchronisation et signe, comme
`offres.py` (#3021) le fait pour les services réels — mais rien d'autre que :
  · SON offre `kind=dataset`, `scope.usage = tv-indices` (créée au premier besoin, conforme aux constantes ci-dessous,
    retirée quand `publier` est faux) ;
  · une version de cette offre (manifeste seulement : l'objet est déjà dans le dépôt de MirrorNet) quand l'empreinte
    change, ou le retrait des versions plus récentes quand le contenu revient à une version antérieure — un geste de
    version au plus par heure ;
  · un abonnement à la DERNIÈRE offre `tv-indices` de chaque AUTRE nœud au niveau de confiance de MirrorNet
    (`confiance_min`, jamais sous LIMITED), gratuite ou réciproque, de durée ≥ 1 h, 64 fournisseurs au plus, un
    abonnement par fournisseur et par heure au plus ; ou, `recevoir` faux, la résiliation de ces abonnements.
Une demande absente, illisible ou invalide, ou une clé absente : aucun geste. Deux passes de suite avec la même demande :
la seconde ne signe rien. L'interrupteur « Recevoir » est le choix du propriétaire ; un refus ou une révocation signés par
le FOURNISSEUR ne sont jamais contournés par un réabonnement de fond.
"""
from __future__ import annotations

import json
import logging
import os
import re
import stat
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional

# Surchargeable pour les tests (variable d'environnement, comme les autres chemins de l'annuaire).
PUBLICATIONS = Path(os.environ.get("ANNUAIRE_MIRRORNET_PUBLICATIONS",
                                   "/var/lib/secubox-mirrornet-partage/publications.json"))
USAGE = "tv-indices"
TAILLE_MAX = 64 * 1024                    # publications.json : quelques centaines d'octets en pratique
OBJET_MAX = 2 * 1024 * 1024               # même plafond que MirrorNet (TAILLE_MAX de locaux.py)
INTERVALLE = timedelta(seconds=3600)      # un geste de version, et un abonnement par fournisseur, au plus par heure
DUREE_MIN_S = 3600                        # offre plus courte : un abonnement par passe, jamais suivie
PRODUCTEURS_MAX = 64                      # même plafond qu'ad-guard (dnstv_indices.PRODUCTEURS_MAX)
TARIFS_ACCEPTES = ("gratuit", "reciproque")
RANG = {"OBSERVER": 0, "LIMITED": 1, "PARTNER": 2, "TRUSTED": 3}   # REVOKED absent : jamais écouté
MOTIF_FOND = "réception des indices TV coupée (tâche de fond)"
MOTIF_RETOUR = "contenu revenu à une version antérieure"

OFFRE = {"kind": "dataset", "approval_mode": "auto", "classe": "communaute", "scope": {"usage": USAGE},
         "description": "Domaines publicité, pistage et télémétrie confirmés par TV Privacy, et domaines légitimes "
                        "(domaine → catégorie, rien d'autre)."}
MANIFESTE = {"classe": "communaute", "format": "application/json", "licence": "CC0-1.0",
             "provenance": "secubox-ad-guard:tv-indices", "donnees_personnelles": "non"}

_EMPREINTE = re.compile(r"^b2:[0-9a-f]{64}\Z")
_log = logging.getLogger("secubox.annuaire.sync")


# --- demande ------------------------------------------------------------------------------------------------------

def _seuil(v: Any) -> Optional[str]:
    """Seuil de confiance demandé : absent → LIMITED ; connu → jamais sous LIMITED ; autre → None (demande invalide)."""
    if v is None:
        return "LIMITED"
    if not isinstance(v, str) or v not in RANG:
        return None
    return v if RANG[v] >= RANG["LIMITED"] else "LIMITED"


def valider(jeu: Any) -> Optional[Dict[str, Any]]:
    """Demande `tv-indices` bien formée, recopiée champ à champ (avec `confiance_min`) ; None sinon (jamais
    d'exception)."""
    if not isinstance(jeu, dict):
        return None
    publier, recevoir, empreinte, taille = (jeu.get(k) for k in ("publier", "recevoir", "empreinte", "taille"))
    seuil = _seuil(jeu.get("confiance_min"))
    if type(publier) is not bool or type(recevoir) is not bool or seuil is None:
        return None
    if empreinte is None and taille is None:
        return {"publier": publier, "recevoir": recevoir, "empreinte": None, "taille": None, "confiance_min": seuil}
    if not (isinstance(empreinte, str) and _EMPREINTE.match(empreinte)
            and type(taille) is int and 0 <= taille <= OBJET_MAX):
        return None
    return {"publier": publier, "recevoir": recevoir, "empreinte": empreinte, "taille": taille, "confiance_min": seuil}


def lire_demandes(chemin: Optional[Path] = None) -> Optional[Dict[str, Any]]:
    """La demande `tv-indices` de `publications.json`, avec le `confiance_min` de MirrorNet : fichier ORDINAIRE (jamais
    un lien), ≤ 64 Kio, JSON strict. Absent, illisible ou invalide : None (aucun geste)."""
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
    jeu = d["jeux"].get(USAGE)
    if not isinstance(jeu, dict) or "confiance_min" in jeu:
        return None
    return valider({**jeu, "confiance_min": d.get("confiance_min")})


# --- lecture du journal -------------------------------------------------------------------------------------------

def _instant(ts: Any) -> Optional[datetime]:
    from annuaire.verbs import _instant as instant  # noqa: PLC0415
    return instant(ts)


def _recent(instants: Iterable[Optional[datetime]], maintenant: datetime) -> bool:
    """Un instant de moins d'une heure ; un instant dans le FUTUR (horloge décalée) ne bloque jamais."""
    return any(t is not None and timedelta(0) <= maintenant - t < INTERVALLE for t in instants)


_EPOQUE = datetime(1970, 1, 1, tzinfo=timezone.utc)


def _cree(o: Dict[str, Any]) -> datetime:
    return _instant(o.get("created_at")) or _EPOQUE


def _usage_tv(o: Dict[str, Any]) -> bool:
    scope = o.get("scope")
    return isinstance(scope, dict) and scope.get("usage") == USAGE


def _est_tv(o: Dict[str, Any]) -> bool:
    return o.get("kind") == "dataset" and _usage_tv(o)


def _conforme(o: Dict[str, Any]) -> bool:
    """Offre propre conforme aux constantes (une offre ancienne ou déviante est remplacée, pas réutilisée)."""
    return _est_tv(o) and o.get("classe") == OFFRE["classe"] and o.get("approval_mode") == OFFRE["approval_mode"]


def _tarif_accepte(o: Dict[str, Any]) -> bool:
    t = o.get("tarif")
    return t is None or (isinstance(t, dict) and t.get("modele") in TARIFS_ACCEPTES)


def _duree_acceptee(o: Dict[str, Any]) -> bool:
    d = o.get("duree_s")
    return d is None or (type(d) is int and d >= DUREE_MIN_S)


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


def abonnements_en_cours(journal, abonne: str, maintenant: Optional[datetime] = None,
                         service_ids: Optional[Iterable[str]] = None) -> Dict[str, List[str]]:
    """service_id → abonnements de `abonne` encore en cours (en attente ou approuvés, non échus), dans l'ordre du
    journal. `service_ids` : ne regarder que ces services (l'état d'un abonnement coûte un balayage du journal). Même
    règle que `_abonnement_en_cours` de l'API (qui s'appuie sur celle-ci)."""
    from annuaire.model import Op, SubscriptionState  # noqa: PLC0415
    from annuaire.verbs import echeance_abonnement, subscription_state  # noqa: PLC0415
    maintenant = maintenant or datetime.now(timezone.utc)
    filtre = set(service_ids) if service_ids is not None else None
    res: Dict[str, List[str]] = {}
    for e in journal.iter_entries(ops=(Op.SERVICE_SUBSCRIBE.value,)):
        p = e.payload
        if e.op != Op.SERVICE_SUBSCRIBE or e.author != abonne or p.get("subscriber") != abonne:
            continue
        if filtre is not None and p.get("service_id") not in filtre:
            continue
        sub_id = p.get("subscription_id")
        if subscription_state(journal, sub_id) not in (SubscriptionState.PENDING, SubscriptionState.APPROVED):
            continue
        ech = _instant(echeance_abonnement(journal, sub_id, maintenant))
        if ech is None or ech > maintenant:
            res.setdefault(p.get("service_id"), []).append(sub_id)
    return res


def _historique(journal, did: str, offres_tv: Dict[str, Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    """fournisseur → {"dernier_le": instant du dernier abonnement de ce nœud à l'une de ses offres tv-indices,
    "refuse": ce dernier abonnement a été refusé ou révoqué par le FOURNISSEUR (signature de celui-ci)}."""
    from annuaire.model import Op  # noqa: PLC0415
    from annuaire.verbs import forme_valide  # noqa: PLC0415
    sub_vers_prov: Dict[str, str] = {}
    hist: Dict[str, Dict[str, Any]] = {}
    clos: set = set()
    for e in journal.iter_entries(ops=("service_subscribe", "service_reject", "service_revoke_offer_sub")):
        p = e.payload
        if e.op == Op.SERVICE_SUBSCRIBE:
            o = offres_tv.get(p.get("service_id"))
            if e.author != did or p.get("subscriber") != did or o is None or not p.get("subscription_id"):
                continue
            prov = o.get("provider")
            if p.get("provider") and p["provider"] != prov:
                continue                                  # lié à un autre fournisseur : sans effet
            sub_vers_prov[p["subscription_id"]] = prov
            h = hist.setdefault(prov, {"dernier_le": None, "dernier": None})
            h["dernier"] = p["subscription_id"]
            t = _instant(p.get("requested_at"))
            if t is not None and (h["dernier_le"] is None or t > h["dernier_le"]):
                h["dernier_le"] = t
            continue
        sub_id = p.get("subscription_id")
        prov = sub_vers_prov.get(sub_id)
        if prov and e.author == prov and forme_valide(e.op, p, e.author):
            clos.add(sub_id)
    return {prov: {"dernier_le": h["dernier_le"], "refuse": h["dernier"] in clos} for prov, h in hist.items()}


def _retraits_le(journal, did: str, sid: str) -> List[Optional[datetime]]:
    from annuaire.verbs import forme_valide  # noqa: PLC0415
    return [_instant(e.payload.get("retracted_at")) for e in journal.iter_entries(ops=("service_dataset_retract",))
            if e.author == did and e.payload.get("service_id") == sid and forme_valide(e.op, e.payload, e.author)]


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
                                offer_service, publish_dataset_version, retract_dataset_version, revoke_offer,
                                subscribe)
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

    def retirer_offre(o: Dict[str, Any], marquer: bool = True) -> None:
        if geste("retrait de l'offre", revoke_offer, journal, priv, did, o["service_id"]) is not None:
            if marquer:
                res["offre"] = "retiree"
            noter("mirrornet_tv_indices_offre_retiree", service_id=o["service_id"])

    vivantes = _get_offers(journal)
    miennes = [o for o in vivantes if o.get("provider") == did and _usage_tv(o)]

    # --- publication : l'offre, puis la version ---------------------------------------------------------------
    if d["publier"]:
        conformes = [o for o in miennes if _conforme(o)]
        sid = None
        if conformes:
            sid, res["offre"] = conformes[0]["service_id"], "existante"
        else:
            nom = _nom(boxname, did)
            o = geste("offre", offer_service, journal, priv, did, name=nom, endpoint=f"mirrornet://{did}/{USAGE}",
                      **{**OFFRE, "scope": dict(OFFRE["scope"])})
            if o is not None:
                sid, res["offre"] = o.service_id, "creee"
                noter("mirrornet_tv_indices_offre_publiee", service_id=sid, nom=nom)
        if sid:
            for o in miennes:                            # une offre propre déviante ne reste pas à côté de la conforme
                if not _conforme(o):
                    retirer_offre(o, marquer=False)
        if sid and d["empreinte"]:
            _version(journal, priv, did, sid, d, maintenant, res, geste, noter, dataset_versions,
                     publish_dataset_version, retract_dataset_version)
    else:
        for o in miennes:
            retirer_offre(o)

    # --- réception : abonnements aux offres tv-indices des AUTRES nœuds, ou leur résiliation ---------------------
    offres_tv = {sid: o for sid, o in _toutes_offres(journal).items() if o.get("provider") != did and _est_tv(o)}
    en_cours = abonnements_en_cours(journal, did, maintenant, service_ids=offres_tv)
    if d["recevoir"]:
        seuil = RANG[d["confiance_min"]]
        niveaux = confiance.niveaux(journal)
        hist = _historique(journal, did, offres_tv)
        dernieres: Dict[str, Dict[str, Any]] = {}       # fournisseur → sa DERNIÈRE offre tv-indices acceptable
        for o in vivantes:
            prov = o.get("provider")
            if (not o.get("service_id") or not prov or prov == did or not _est_tv(o) or o.get("classe") == "prive"
                    or not _tarif_accepte(o) or not _duree_acceptee(o)):
                continue
            if RANG.get(niveaux.get(prov, ("OBSERVER", ""))[0], -1) < seuil or hist.get(prov, {}).get("refuse"):
                continue
            prec = dernieres.get(prov)
            if prec is None or _cree(o) >= _cree(prec):          # à égalité : la plus loin dans le journal
                dernieres[prov] = o
        suivis = {offres_tv[sid]["provider"] for sid in en_cours if sid in offres_tv}
        # Plafond : les fournisseurs déjà suivis d'abord, puis les autres dans un ordre stable.
        for prov in sorted(dernieres, key=lambda p: (p not in suivis, p))[:PRODUCTEURS_MAX]:
            o = dernieres[prov]
            sid = o["service_id"]
            if sid in en_cours or _recent([hist.get(prov, {}).get("dernier_le")], maintenant):
                continue
            duree = o.get("duree_s")
            expire = (maintenant + timedelta(seconds=duree)).isoformat() if type(duree) is int else None
            s = geste("abonnement", subscribe, journal, priv, did, sid, tarif_accepte=o.get("tarif"),
                      expire_le=expire, provider=prov)
            if s is not None:
                res["abonnements"] += 1
                noter("mirrornet_tv_indices_abonnement", subscription_id=s.subscription_id, service_id=sid,
                      fournisseur=prov)
    else:
        for sid, subs in en_cours.items():
            o = offres_tv.get(sid)
            if o is None:
                continue
            for sub_id in subs:
                if geste("résiliation", cancel_subscription, journal, priv, did, sub_id, MOTIF_FOND) is not None:
                    res["resiliations"] += 1
                    noter("mirrornet_tv_indices_resiliation", subscription_id=sub_id, service_id=sid,
                          fournisseur=o.get("provider"))
    return res


def _version(journal, priv, did, sid, d, maintenant, res, geste, noter, dataset_versions, publish_dataset_version,
             retract_dataset_version) -> None:
    """Un geste de version au plus par heure (dernière version ou dernier retrait) :
    - empreinte = version courante (dernière non retirée) : rien ;
    - empreinte = version ANTÉRIEURE non retirée (A → B → A) : retrait des versions plus récentes, A redevient courante ;
    - empreinte jamais publiée : nouvelle version ;
    - empreinte d'une version retirée : rien (une version est immuable, un retrait définitif)."""
    empreinte = d["empreinte"]
    versions = dataset_versions(journal, sid)
    actives = [v for v in versions if not v.get("retiree")]
    if actives and actives[-1].get("empreinte") == empreinte:
        return
    gestes_le = [_instant(v.get("cree_le")) for v in versions] + _retraits_le(journal, did, sid)
    if _recent(gestes_le, maintenant):
        return
    rang = next((i for i, v in enumerate(actives) if v.get("empreinte") == empreinte), None)
    if rang is not None:
        retirees = 0
        for v in reversed(actives[rang + 1:]):
            if geste("retrait de version", retract_dataset_version, journal, priv, did, sid, v["empreinte"],
                     MOTIF_RETOUR) is not None:
                retirees += 1
                noter("mirrornet_tv_indices_version_retiree", service_id=sid, numero=v.get("numero"),
                      empreinte=v["empreinte"], motif=MOTIF_RETOUR)
        if retirees == len(actives) - rang - 1:
            res["version"] = empreinte
        return
    if any(v.get("empreinte") == empreinte for v in versions):
        return
    v = geste("version", publish_dataset_version, journal, priv, did, sid, empreinte=empreinte, taille=d["taille"],
              **MANIFESTE)
    if v is not None:
        res["version"] = empreinte
        noter("mirrornet_tv_indices_version_publiee", service_id=sid, numero=v.numero, empreinte=empreinte,
              taille=d["taille"])
