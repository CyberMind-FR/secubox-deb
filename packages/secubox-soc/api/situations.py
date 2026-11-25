# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Situations de la Vigie SOC (#3963) : ce qui se passe, trié par urgence. Lecture seule, aucun balayage de journal.

Sources, toutes déjà calculées ailleurs : WAF (`/dossiers/sites` pour les sites sous attaque et les décisions en attente,
`/populations` pour les campagnes), actord (propositions de SADE) et la base de décisions, santé (`health-doctor.json`,
`health/status.json`). Les identifiants de l'appelant sont retransmis au WAF tels quels, comme la façade SADE.

Une source injoignable, trop ancienne ou périmée est DITE dans `sources` et n'est jamais lue comme « rien à signaler » :
les chiffres qui en dépendent valent null. Les phrases sont construites ici à partir de mesures ; aucune adresse ne sort."""
import asyncio
import hashlib
import json
import os
import re
import stat
import threading
import time
from collections import OrderedDict
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from fastapi import APIRouter, Depends, Request

from secubox_core.auth import require_lecture

from . import defense, defense_etat, substrat

router = APIRouter(tags=["situations"])

TTL_S = 30.0
CACHE_MAX = 64
DELAI_S = 4.0
SITES_MAX, POPULATIONS_MAX, VITAUX_MAX, LENTS_MAX = 6, 12, 8, 8
SANTE_FRAICHE_S = 600
TAILLE_MAX = 4 * 1024 * 1024
POPULATIONS_FRAICHES_S = 2 * 3600
DEFAUTS = {"SECUBOX_SOC_SANTE": "/var/cache/secubox/health-doctor.json",
           "SECUBOX_SOC_SANTE_SITES": "/var/cache/secubox/health/status.json"}

FAMILLES = {"collecte": "Collecte", "messagerie": "Mots de passe sur la messagerie",
            "acces_distant": "Balayage des leurres de service", "balayage_web": "Balayage des sites web",
            "autre": "Autre activité"}
GESTES_FAMILLE = {"collecte": "Recopie du contenu", "messagerie": "Essais de mots de passe sur la messagerie",
                  "acces_distant": "Essais sur les leurres de service", "balayage_web": "Sondes de chemins de sites web",
                  "autre": "Activité hostile"}
CLASSES = {"proxy_loue": "Relais loués", "hebergeur": "Hébergeurs", "acces": "Accès grand public",
           "mobile_partage": "Mobile ou satellite", "cdn": "Réseaux de diffusion", "relais_vie_privee": "Relais de vie privée",
           "scanner_recherche": "Balayeurs de recherche", "inconnu": "Réseau inconnu"}
GESTES = {"ban": ("bannissement", "bannissements"), "limiter": ("ralentissement", "ralentissements"),
          "leurre": ("envoi vers un leurre", "envois vers un leurre"), "prolonger": ("prolongation", "prolongations")}
VITAUX = {"haproxy": "L’entrée du site (HAProxy)", "nginx": "Le serveur web (nginx)", "secubox-metrics": "Les mesures de la box",
          "secubox-hub": "Le tableau de bord", "gitea-lxc": "Le dépôt de code", "mail-lxc": "Le courrier",
          "cookie-audit-ledger": "Le registre des cookies", "filesystems": "Les disques", "waf-selftest": "L’essai de blocage du WAF",
          "clamav": "L’antivirus"}

_NOM = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,252}$")
_POP_ID = re.compile(r"^[A-Za-z0-9:_-]{1,96}$")
_ADRESSE = re.compile(r"(?<![\w.])(?:\d{1,3}(?:\.\d{1,3}){3}|(?:[0-9a-fA-F]{0,4}:){3,7}[0-9a-fA-F]{0,4})(?![\w.])")


# ── français ─────────────────────────────────────────────────────────────────────────────────────────────────────

def nb(n: Any) -> str:
    return f"{int(n):,}".replace(",", " ")


def pl(n: int, sing: str, plur: str) -> str:
    return f"{nb(n)} {sing if abs(int(n)) < 2 else plur}"


def _entier(v: Any) -> Optional[int]:
    return v if isinstance(v, int) and not isinstance(v, bool) and v >= 0 else None


def _n(v: Any) -> int:
    return _entier(v) or 0


def _texte(v: Any, taille: int = 200) -> str:
    """Texte venu d'une source, borné ; une adresse n'en sort jamais."""
    s = v if isinstance(v, str) else ""
    return _ADRESSE.sub("adresse masquée", "".join(c if c.isprintable() else " " for c in s))[:taille]


# ── sources ──────────────────────────────────────────────────────────────────────────────────────────────────────

class Sources:
    """État de lecture de chaque source, dans l'ordre d'affichage."""

    def __init__(self):
        self.l: "OrderedDict[str, Dict[str, Any]]" = OrderedDict()

    def dire(self, ident: str, nom: str, erreur: Optional[str] = None) -> None:
        self.l[ident] = {"id": ident, "nom": nom, "ok": erreur is None, "erreur": erreur}

    def ok(self, *idents: str) -> bool:
        return all(self.l.get(i, {}).get("ok") for i in idents)


def _motif(r: Dict[str, Any]) -> str:
    e = str(r.get("erreur") or "")
    if e.startswith("http 404"):
        return "mesure absente de cette version"
    if e.startswith(("http 401", "http 403")):
        return "lecture refusée"
    if e == "délai":
        return "ne répond pas à temps"
    return "injoignable"


def _lire_waf(chemin: str, entetes: Dict[str, str]) -> Dict[str, Any]:
    r = substrat.lire("waf", chemin, entetes=entetes, delai=DELAI_S)
    if r["ok"] and not isinstance(r["donnees"], dict):
        return {"ok": False, "donnees": None, "erreur": "réponse inattendue"}
    return r


def _fichier(var: str) -> Tuple[Any, Optional[str]]:
    """JSON d'un fichier ordinaire (jamais un lien), borné. (donnée, motif)."""
    try:
        fd = os.open(os.environ.get(var) or DEFAUTS[var], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    except FileNotFoundError:
        return None, "aucune mesure"
    except OSError:
        return None, "illisible"
    try:
        with os.fdopen(fd, "rb") as f:
            if not stat.S_ISREG(os.fstat(f.fileno()).st_mode):
                return None, "illisible"
            brut = f.read(TAILLE_MAX + 1)
        return (json.loads(brut.decode("utf-8")), None) if len(brut) <= TAILLE_MAX else (None, "illisible")
    except (OSError, UnicodeDecodeError, ValueError, RecursionError):
        return None, "illisible"


def _epoque(v: Any) -> Optional[int]:
    if not isinstance(v, str) or len(v) > 40:
        return None
    try:
        d = datetime.fromisoformat(v.replace("Z", "+00:00"))
    except ValueError:
        return None
    return int((d if d.tzinfo else d.replace(tzinfo=timezone.utc)).timestamp())


# ── fabrique ─────────────────────────────────────────────────────────────────────────────────────────────────────

def _situation(ident: str, titre: str, sous: str, etiquettes: List[List[str]], urgence: int, phrase: str, **k: Any) -> Dict[str, Any]:
    vide = {"serie": None, "serie_jours": None, "serie_note": None, "couches": None, "debut": None, "pas": 3600, "partielles": [],
            "attaque": False, "chaine": [], "categories": [], "origine": {"unite": "", "lignes": []}, "faits": [], "geste": None,
            "poids": 0}
    return {**vide, "id": ident, "titre": titre, "sous_titre": sous, "etiquettes": etiquettes, "urgence": urgence, "phrase": phrase, **k}


def _geste(libelle: str, href: str, note: str, genre: str = "") -> Dict[str, str]:
    return {"libelle": libelle, "href": href, "note": note, "genre": genre}


_ACTOR = ("Voir ce qui serait banni", "/actor/", "Ouvre Actor. Rien n’est posé avant ta confirmation.", "r")


def _population(p: Dict[str, Any], rotation: Dict[str, Dict[str, Any]], propose: bool) -> Optional[Dict[str, Any]]:
    ident = p.get("id")
    if not isinstance(ident, str) or not _POP_ID.match(ident) or p.get("etat") == "inactive" or not _n(p.get("actives_24h")):
        return None
    fam = p.get("famille") if p.get("famille") in FAMILLES else "autre"
    cible = _texte(p.get("nom_cible"), 120)
    nom = FAMILLES[fam] + (f" : {cible}" if cible and fam != "messagerie" else "")
    n, act, ban = _n(p.get("adresses")), _n(p.get("actives_24h")), _n(p.get("bannies_24h"))
    une, reseaux, tourne = _n(p.get("une")), _n(p.get("reseaux")), p.get("rotation") is True
    camp = rotation.get(ident)
    a_bannir = _n(camp.get("a_bannir")) if camp and propose else 0
    bannie = p.get("etat") == "bannie"
    serie = p.get("serie") if isinstance(p.get("serie"), list) and len(p["serie"]) == 7 else []
    jours = [_entier(v) for v in serie]
    etiq = ([["à décider", "r"]] if a_bannir else []) + ([["adresses tournantes", "o"]] if tourne else []) + \
        ([["bannie", "v"]] if bannie else [["observée", "o" if tourne else ""]])
    ou = f" sur {cible}" if cible and fam != "messagerie" else ""
    de = f" de {pl(reseaux, 'réseau', 'réseaux')}" if reseaux else ""
    phrase = [f"{GESTES_FAMILLE[fam]}{ou} depuis {pl(n, 'adresse', 'adresses')}{de} en sept jours."]
    if tourne and une:
        phrase.append(f"{une} % des adresses n’ont été vues qu’une fois.")
    if ban >= act:
        phrase.append("La seule active depuis 24 h est bannie." if act == 1 else f"Les {nb(act)} actives depuis 24 h sont toutes bannies.")
    else:
        phrase.append(f"{pl(act, 'est active', 'sont actives')} depuis 24 h, "
                      + ("aucune n’est bannie." if not ban else f"{nb(ban)} {'est bannie' if ban < 2 else 'sont bannies'}."))
    avant = [v for v in jours[:-2] if v is not None] if len(jours) == 7 else []
    if len(jours) == 7 and jours[-2] is not None and avant:
        moy = round(sum(avant) / len(avant))
        phrase.append(f"Hier : {pl(jours[-2], 'tentative', 'tentatives')}, contre {nb(moy)} par jour en moyenne les jours d’avant.")
    if a_bannir:
        phrase.append(f"{pl(a_bannir, 'adresse est proposée', 'adresses sont proposées')} au bannissement et "
                      f"{'attend' if a_bannir < 2 else 'attendent'} ta décision.")
    faits = []
    if _n(p.get("premier")):
        faits.append({"ts": p["premier"], "texte": "Première tentative de la période", "preuve": "relevé des populations"})
    if camp and _n(camp.get("etablie_le")):
        faits.append({"ts": camp["etablie_le"], "texte": f"Campagne à adresses tournantes reconnue : {pl(_n(camp.get('sources')), 'adresse', 'adresses')}",
                      "preuve": "détecteur de rotation"})
    if a_bannir and _n(camp.get("dernier")):
        faits.append({"ts": camp["dernier"], "texte": pl(a_bannir, "adresse proposée au bannissement", "adresses proposées au bannissement"),
                      "preuve": "attend ta décision"})
    if _n(p.get("dernier")):
        faits.append({"ts": p["dernier"], "texte": "Dernière tentative vue", "preuve": "relevé des populations"})
    faits.sort(key=lambda f: f["ts"])
    classes = p.get("classes") if isinstance(p.get("classes"), dict) else {}
    return _situation(
        "population:" + ident, nom, f"{pl(act, 'adresse active', 'adresses actives')} en 24 h", etiq,
        100 if a_bannir else 35 if bannie else 70 if tourne else 50, " ".join(phrase),
        serie_jours=jours if any(v is not None for v in jours) else None,
        serie_note="Cette campagne est mesurée par jour, pas par heure ; la journée en cours est partielle.",
        chaineTitre="Les adresses, de la vue au blocage",
        chaine=[{"nom": "Vues en sept jours", "n": n, "cle": "recues", "def": "Adresses distinctes de la population."},
                {"nom": "Actives depuis 24 h", "n": act, "cle": "hostiles", "def": "Adresses revues depuis 24 h."},
                {"nom": "Bannies depuis 24 h", "n": ban, "cle": "arrete", "def": "Adresses actives bannies depuis 24 h."}],
        origine={"unite": "%", "lignes": [{"cle": c, "nom": CLASSES[c], "n": _n(v)} for c, v in classes.items() if c in CLASSES]},
        faits=faits, poids=act,
        geste=_geste(*_ACTOR) if a_bannir else _geste("Ouvrir la campagne dans le WAF", "/waf/#campaigns", "Le détail de la population vit dans le WAF."))


def _site(d: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    ident = d.get("id")
    if not isinstance(ident, str) or not _NOM.match(ident):
        return None
    prendre = ("serie", "couches", "chaine", "categories", "faits", "debut", "pas", "partielles", "attaque")
    origine = d.get("origine") if isinstance(d.get("origine"), dict) else {"unite": "", "lignes": []}
    # « à décider » est porté par la campagne : une décision ne se compte pas deux fois
    etiq = [[_texte(t[0], 40), t[1]] for t in d.get("etiquettes", []) if isinstance(t, list) and len(t) == 2 and t[0] != "à décider"]
    faits = [{"ts": f.get("ts"), "texte": _texte(f.get("texte")), "preuve": _texte(f.get("preuve"), 60)}
             for f in d.get("faits", []) if isinstance(f, dict)]
    return _situation("site:" + ident, _texte(d.get("titre"), 253), _texte(d.get("sous_titre")), etiq, 80, _texte(d.get("phrase"), 1200),
                      **{**{k: d[k] for k in prendre if k in d}, "faits": faits}, origine=origine, poids=_n(d.get("total")), chaineTitre="Le mur, en 24 h",
                      geste=_geste("Ouvrir le dossier du site", "/waf/#sites:" + ident, "Le détail par site vit dans le WAF."))


def _candidats(cle: str, d: Any) -> Optional[Dict[str, Any]]:
    """Adresses que les bans automatiques proposent sans les poser (mode propose)."""
    if not isinstance(d, dict) or d.get("etat") != "ok" or d.get("mode") != "propose" or not _n(d.get("a_bannir")):
        return None
    n = d["a_bannir"]
    origine = "par les campagnes corrélées" if cle == "campagnes" else "par le suivi des acteurs"
    return _situation(
        "candidats:" + cle, "Adresses proposées au bannissement", f"{pl(n, 'adresse', 'adresses')}, {origine}", [["à décider", "r"]], 95,
        f"{pl(n, 'adresse est proposée', 'adresses sont proposées')} au bannissement {origine}. Le mode est « proposer » : rien n’est posé.",
        chaine=[{"nom": "Proposées", "n": n, "cle": "passe", "def": "Adresses distinctes à bannir selon l’état publié."},
                {"nom": "Déjà bannies", "n": _entier(d.get("bannis")), "cle": "arrete", "def": "Adresses distinctes déjà bannies."}],
        faits=[{"ts": d["genere_le"], "texte": "État publié par le pare-feu", "preuve": "pare-feu"}] if _n(d.get("genere_le")) else [],
        poids=n, geste=_geste(*_ACTOR))


def _rotation_seule(c: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Campagne à adresses tournantes qui propose des bans et n'a pas (encore) de population au relevé."""
    n, hote = _n(c.get("a_bannir")), _texte(c.get("hote"), 253)
    if not n or not hote:
        return None
    return _situation(
        "rotation:" + _texte(c.get("id"), 32), "Adresses tournantes : " + hote, f"{pl(n, 'adresse proposée', 'adresses proposées')} au bannissement",
        [["à décider", "r"], ["adresses tournantes", "o"]], 100,
        f"Campagne reconnue à {pl(_n(c.get('sources')), 'adresse', 'adresses')}. {pl(n, 'est proposée', 'sont proposées')} au bannissement et "
        f"{'attend' if n < 2 else 'attendent'} ta décision.",
        chaine=[{"nom": "Vues", "n": _entier(c.get("sources")), "cle": "recues"}, {"nom": "Épargnées", "n": _entier(c.get("epargnees")), "cle": "hostiles"},
                {"nom": "Proposées", "n": n, "cle": "passe"}, {"nom": "Bannies", "n": _entier(c.get("bannies")), "cle": "arrete"}],
        faits=[{"ts": c[k], "texte": t, "preuve": "détecteur de rotation"} for k, t in
               (("etablie_le", "Campagne reconnue"), ("dernier", "Dernière adresse vue")) if _n(c.get(k))],
        poids=n, geste=_geste(*_ACTOR))


def _sade(s: Sources) -> Optional[Dict[str, Any]]:
    """Propositions de SADE en attente (même règle que /defense/proposals : sans décision, ou à redécider)."""
    r = defense._lire_propositions()
    if not r["ok"]:
        s.dire("sade", "Propositions de SADE", _motif(r))
        return None
    try:
        etats = defense_etat.etats_decisions()
        mode = defense_etat.mode_courant()
    except defense_etat.EtatIndisponible:
        s.dire("sade", "Propositions de SADE", "base des décisions illisible")
        return None
    s.dire("sade", "Propositions de SADE")
    attente = [p for p in defense._propositions(r) if p["geste"] in GESTES and etats.get(p["empreinte"], "en_attente") == "en_attente"]
    if not attente:
        return None
    n, par = len(attente), {g: sum(p["geste"] == g for p in attente) for g in GESTES}
    detail = ", ".join(pl(k, *GESTES[g]) for g, k in par.items() if k)
    scores = [p["score"] for p in attente if p["score"] is not None]
    demande = mode in ("reactive", "active")
    d = r["donnees"] if isinstance(r["donnees"], dict) else {}
    ts = d.get("genere_le")
    return _situation(
        "sade", "Propositions de SADE", f"{pl(n, 'geste proposé', 'gestes proposés')}", [["à décider", "r"]] if demande else [["observation", ""]],
        90 if demande else 25,
        f"SADE propose {pl(n, 'geste', 'gestes')} : {detail}." + (f" Le score le plus haut est {max(scores)} sur 100." if scores else "")
        + (f" {'Il attend' if n < 2 else 'Ils attendent'} ta décision." if demande else " SADE est en observation : rien ne t’est demandé."),
        chaineTitre="Les gestes proposés", chaine=[{"nom": GESTES[g][0][:1].upper() + GESTES[g][0][1:], "n": k, "cle": "passe"} for g, k in par.items() if k],
        faits=[{"ts": int(ts), "texte": "Propositions recalculées", "preuve": "SADE"}] if isinstance(ts, (int, float)) and not isinstance(ts, bool) and ts > 0 else [],
        poids=n, geste=_geste("Ouvrir les propositions", "/soc/#tdef", "Chaque geste se décide un par un, dans Cyber Defense Live.", "r" if demande else ""))


def _sante(s: Sources, maintenant: float) -> List[Dict[str, Any]]:
    """Services vitaux en échec et sites lents ou muets : seulement ce qu'une mesure fraîche dit."""
    out: List[Dict[str, Any]] = []
    d, motif = _fichier("SECUBOX_SOC_SANTE")
    ts = _epoque(d.get("generated_at")) if isinstance(d, dict) else None
    if motif is None and (ts is None or not isinstance(d.get("checks"), dict)):
        motif = "illisible"
    if motif is None and maintenant - ts > SANTE_FRAICHE_S:
        motif = "mesure périmée"
    s.dire("sante", "Santé des services vitaux", motif)
    if motif is None:
        pannes = [c for c, e in d["checks"].items() if isinstance(e, dict) and e.get("ok") is False and e.get("niveau") != "avertissement"
                  and isinstance(c, str) and _NOM.match(c)]
        for c in pannes[:VITAUX_MAX]:
            nom = VITAUX.get(c, c)
            out.append(_situation(
                "vital:" + c, nom, "Contrôle en échec", [["service en échec", "r"]], 85,
                f"Le contrôle « {c} » échoue au dernier passage. Les contrôles passent chaque minute.",
                faits=[{"ts": ts, "texte": "Contrôle en échec", "preuve": "contrôle de santé"}], poids=1,
                geste=_geste("Ouvrir la Santé", "/health/", "Le détail et le bouton « Réparer » vivent dans la page Santé.", "r")))
    d, motif = _fichier("SECUBOX_SOC_SANTE_SITES")
    ts = _epoque(d.get("timestamp")) if isinstance(d, dict) else None
    if motif is None and (ts is None or not isinstance(d.get("vhosts"), dict)):
        motif = "illisible"
    if motif is None and maintenant - ts > SANTE_FRAICHE_S:
        motif = "mesure périmée"
    s.dire("sante_sites", "Temps de réponse des sites", motif)
    if motif is None:
        sites = [(n, v) for n, v in d["vhosts"].items() if isinstance(n, str) and _NOM.match(n) and isinstance(v, dict)]
        lents = sorted(((n, float(v["latency_ms"])) for n, v in sites if v.get("status") == "slow"
                        and isinstance(v.get("latency_ms"), (int, float)) and not isinstance(v.get("latency_ms"), bool)), key=lambda x: -x[1])
        # « down » compte aussi les refus voulus (401, 403, 404) : seuls un délai dépassé ou une erreur 5xx disent une panne
        muets = sorted(n for n, v in sites if v.get("status") == "down" and (v.get("error") == "timeout" or _n(v.get("status_code")) >= 500))
        if muets:
            out.append(_situation(
                "sites-muets", "Sites sans réponse", pl(len(muets), "site", "sites"), [["service en échec", "r"]], 82,
                f"{pl(len(muets), 'site ne répond', 'sites ne répondent')} pas ou {'rend' if len(muets) < 2 else 'rendent'} une erreur au dernier contrôle : "
                + _liste_noms(muets) + ".",
                faits=[{"ts": ts, "texte": n, "preuve": "contrôle de santé"} for n in muets[:LENTS_MAX]], poids=len(muets),
                geste=_geste("Ouvrir la Santé", "/health/", "Le détail par site vit dans la page Santé.", "r")))
        if lents:
            out.append(_situation(
                "sites-lents", "Sites lents", pl(len(lents), "site", "sites"), [["service lent", "o"]], 55,
                f"{pl(len(lents), 'site dépasse', 'sites dépassent')} le seuil de réponse au dernier contrôle. Le plus lent est {lents[0][0]}, "
                f"à {nb(round(lents[0][1]))} ms.",
                chaineTitre="Temps de réponse (ms)", chaine=[{"nom": n, "n": round(v), "cle": "passe"} for n, v in lents[:LENTS_MAX]],
                faits=[{"ts": ts, "texte": f"{n} : {nb(round(v))} ms", "preuve": "contrôle de santé"} for n, v in lents[:LENTS_MAX]], poids=len(lents),
                geste=_geste("Ouvrir la Santé", "/health/", "Le détail par site vit dans la page Santé.")))
    return out


def _liste_noms(noms: List[str], n: int = 3) -> str:
    vus = ", ".join(noms[:n])
    return vus if len(noms) <= n else f"{vus} et {pl(len(noms) - n, 'autre', 'autres')}"


def calculer(entetes: Dict[str, str], maintenant: float) -> Dict[str, Any]:
    s, out = Sources(), []
    r = _lire_waf("/dossiers/sites", entetes)
    sites = r["donnees"] if r["ok"] else None
    if sites is not None and sites.get("disponible") is not True:
        s.dire("waf_sites", "WAF, relevé par site", "premier relevé en cours")
        sites = None
    elif sites is None:
        s.dire("waf_sites", "WAF, relevé par site", _motif(r))
    elif sites.get("perime") is True or sites.get("journal") == "illisible":
        s.dire("waf_sites", "WAF, relevé par site", "relevé figé")
    else:
        s.dire("waf_sites", "WAF, relevé par site")
    dec = sites.get("decisions") if sites and isinstance(sites.get("decisions"), dict) else {}
    rot = dec.get("rotation") if isinstance(dec.get("rotation"), dict) else {}
    camps = {c["id"]: c for c in rot.get("campagnes", []) if isinstance(c, dict) and isinstance(c.get("id"), str)}
    propose = rot.get("mode") == "propose" and rot.get("etat") == "ok"

    r = _lire_waf("/populations", entetes)
    pops: List[Dict[str, Any]] = []
    if not r["ok"]:
        s.dire("waf_populations", "WAF, campagnes", _motif(r))
    elif r["donnees"].get("disponible") is not True or not isinstance(r["donnees"].get("populations"), list):
        s.dire("waf_populations", "WAF, campagnes", "aucun relevé")
    else:
        age = _entier(r["donnees"].get("age_s"))
        s.dire("waf_populations", "WAF, campagnes", "relevé figé" if age is None or age > POPULATIONS_FRAICHES_S else None)
        pops = [x for x in (_population(p, camps, propose) for p in r["donnees"]["populations"] if isinstance(p, dict)) if x]
    pops.sort(key=lambda x: (-x["urgence"], -x["poids"]))
    out += pops[:POPULATIONS_MAX]
    couvertes = {x["id"].split(":", 1)[1] for x in pops}
    if propose:
        out += [x for x in (_rotation_seule(c) for i, c in camps.items() if i not in couvertes) if x]
    out += [x for x in (_candidats(k, dec.get(k)) for k in ("campagnes", "acteurs")) if x]

    attaques = [x for x in (sites or {}).get("sites", []) if isinstance(x, dict) and x.get("attaque") is True
                and isinstance(x.get("id"), str) and _NOM.match(x["id"]) and x["id"] != "noms-inconnus"]
    muet = False
    for x in attaques[:SITES_MAX]:
        d = {"ok": False} if muet else _lire_waf("/dossiers/sites/" + x["id"], entetes)
        muet = muet or not d["ok"]     # un détail qui ne vient pas : les suivants ne sont pas attendus
        v = _site(d["donnees"] if d["ok"] and d["donnees"].get("disponible") is True else {**x, "phrase": "Site sous attaque. Le détail n’a pas pu être lu."})
        if v:
            out.append(v)
    sade = _sade(s)
    if sade:
        out.append(sade)
    out += _sante(s, maintenant)
    out.sort(key=lambda x: (-x["urgence"], -x["poids"], x["titre"]))

    ch = sites.get("chiffres") if sites and isinstance(sites.get("chiffres"), dict) else {}
    series = ch.get("series") if isinstance(ch.get("series"), dict) else {}
    decideurs, a_decider = s.ok("waf_sites", "sade"), sum(1 for x in out if ["à décider", "r"] in x["etiquettes"])
    complet = all(x["ok"] for x in s.l.values())
    return {
        "genere_le": int(maintenant), "situations": out, "sources": list(s.l.values()),
        "complet": complet, "autres_populations": max(0, len(pops) - POPULATIONS_MAX),
        "chiffres": {
            # une source muette : le compte connu est un minimum annoncé ; sans rien de connu, null (jamais 0)
            "a_decider": a_decider if decideurs or a_decider else None, "a_decider_partiel": not decideurs,
            "en_cours": len(out) if complet or out else None, "en_cours_partiel": not complet,
            "ecartees_24h": _entier(ch.get("ecartees")), "passees_24h": _entier(ch.get("passees")),
            "series": {"ecartees": series.get("ecartees"), "passees": series.get("passees")},
            "heures_mesurees": _entier((sites or {}).get("heures_mesurees"))},
    }


# ── service : cache court, un seul calcul à la fois par appelant ──────────────────────────────────────────────────

_CACHE: "OrderedDict[str, Tuple[float, Dict[str, Any]]]" = OrderedDict()
_VERROU = threading.Lock()
_CALCUL = threading.Lock()


def vider() -> None:
    with _VERROU:
        _CACHE.clear()


def _frais(cle: str) -> Optional[Dict[str, Any]]:
    with _VERROU:
        e = _CACHE.get(cle)
        return e[1] if e is not None and 0 <= time.monotonic() - e[0] < TTL_S else None


def servir(entetes: Dict[str, str]) -> Dict[str, Any]:
    cle = hashlib.sha256("\0".join(f"{k}={v}" for k, v in sorted(entetes.items())).encode()).hexdigest()
    p = _frais(cle)
    if p is not None:
        return p
    with _CALCUL:
        p = _frais(cle)
        if p is None:
            p = calculer(entetes, time.time())
            with _VERROU:
                _CACHE.pop(cle, None)
                while len(_CACHE) >= CACHE_MAX:
                    _CACHE.popitem(last=False)
                _CACHE[cle] = (time.monotonic(), p)
    return p


@router.get("/situations", dependencies=[Depends(require_lecture)])
async def situations(request: Request):
    """Les situations, de la plus urgente à la plus calme, et l'état de lecture de chaque source."""
    p = await asyncio.to_thread(servir, defense._entetes_appelant(request))
    return {**p, "age_s": max(0, int(time.time() - p["genere_le"]))}
