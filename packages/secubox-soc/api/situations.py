# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Situations de la Vigie SOC (#3963) : ce qui se passe, trié par urgence. Lecture seule, aucun balayage de journal.

Sources, toutes déjà calculées ailleurs : WAF (`/dossiers/sites` pour les sites sous attaque et les décisions en attente,
`/populations` pour les campagnes), actord (propositions de SADE) et la base de décisions, santé (`health-doctor.json`,
`health/status.json`). Les identifiants de l'appelant sont retransmis au WAF tels quels, comme la façade SADE.

Une source injoignable, trop ancienne ou périmée est DITE dans `sources` et n'est jamais lue comme « rien à signaler » :
les chiffres qui en dépendent valent null. Les noms de services et de
sites relevés par la Santé sont un inventaire : administrateur réel seulement. Les phrases sont construites ici à partir de mesures ; aucune adresse ne sort."""
import asyncio
import hashlib
import json
import os
import re
import stat
import threading
import time
from collections import OrderedDict
from concurrent.futures import Future, ThreadPoolExecutor
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple
from zoneinfo import ZoneInfo

from fastapi import APIRouter, Depends, HTTPException, Request

from secubox_core.auth import ENTETE_LAN, SESSION_COOKIE, require_lecture

from . import defense, defense_etat, substrat

router = APIRouter(tags=["situations"])

TTL_S = 30.0
CACHE_MAX = 64
DELAI_S = 4.0
ECHEANCE_S = 12.0        # un calcul entier, toutes sources comprises
ATTENTE_S = 14.0         # une requête n'attend pas plus ; au-delà, 503
FILS, FILE_MAX = 2, 6    # fils dédiés (jamais ceux de to_thread) et calculs en cours ou en file, toutes clés comprises
PARIS = ZoneInfo("Europe/Paris")
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


def _lire_waf(chemin: str, entetes: Dict[str, str], echeance: float) -> Dict[str, Any]:
    r = substrat.lire("waf", chemin, entetes=entetes, delai=DELAI_S, echeance=echeance)
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
    vide = {"serie": None, "serie_jours": None, "serie_note": None, "jours_fin": None, "couches": None, "debut": None, "pas": 3600, "partielles": [],
            "attaque": False, "chaine": [], "categories": [], "origine": {"unite": "", "lignes": []}, "faits": [], "geste": None,
            "poids": 0}
    return {**vide, "id": ident, "titre": titre, "sous_titre": sous, "etiquettes": etiquettes, "urgence": urgence, "phrase": phrase, **k}


def _geste(libelle: str, href: str, note: str, genre: str = "") -> Dict[str, str]:
    return {"libelle": libelle, "href": href, "note": note, "genre": genre}


_ACTOR = ("Voir ce qui serait banni", "/actor/", "Ouvre Actor. Rien n’est posé avant ta confirmation.", "r")


def _cible(nom: Any, servies: Optional[set]) -> str:
    """Nom d'un site que le WAF sert ; sinon un nom venu de l'attaquant, jamais recopié. Sans relevé du WAF, rien à dire."""
    if not isinstance(nom, str) or not nom or servies is None:
        return ""
    return nom if nom in servies and _NOM.match(nom) else "un nom non servi"


def _population(p: Dict[str, Any], rotation: Dict[str, Dict[str, Any]], propose: bool, servies: Optional[set], releve: Optional[int],
                maintenant: float) -> Optional[Dict[str, Any]]:
    ident = p.get("id")
    if not isinstance(ident, str) or not _POP_ID.match(ident) or p.get("etat") == "inactive" or not _n(p.get("actives_24h")):
        return None
    fam = p.get("famille")
    fam = fam if isinstance(fam, str) and fam in FAMILLES else "autre"
    cible = _cible(p.get("nom_cible"), servies) if fam not in ("messagerie", "acces_distant") else ""     # là, la cible est un compte
    nom = FAMILLES[fam] + (f" : {cible}" if cible else "")
    n, act, ban = _n(p.get("adresses")), _n(p.get("actives_24h")), _n(p.get("bannies_24h"))
    une, reseaux, tourne = _n(p.get("une")), _n(p.get("reseaux")), p.get("rotation") is True
    camp = rotation.get(ident)
    a_bannir = _n(camp.get("a_bannir")) if camp and propose else 0
    bannie = p.get("etat") == "bannie"
    serie = p.get("serie") if isinstance(p.get("serie"), list) and len(p["serie"]) == 7 else []
    jours = [_entier(v) for v in serie]
    etiq = ([["à décider", "r"]] if a_bannir else []) + ([["adresses tournantes", "o"]] if tourne else []) + \
        ([["bannie", "v"]] if bannie else [["observée", "o" if tourne else ""]])
    ou = f" sur {cible}" if cible else ""
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
    # la dernière case est le jour du RELEVÉ : juste après minuit ce n'est pas aujourd'hui, et « hier » n'est pas encore complet
    meme_jour = releve is not None and datetime.fromtimestamp(releve, PARIS).date() == datetime.fromtimestamp(maintenant, PARIS).date()
    if meme_jour and len(jours) == 7 and jours[-2] is not None and avant:
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
        serie_jours=jours if any(v is not None for v in jours) else None, jours_fin=releve,
        serie_note="Cette campagne est mesurée par jour, pas par heure ; la dernière journée du relevé est partielle.",
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
    n, hote = _n(c.get("a_bannir")), c.get("hote")
    if not n:
        return None
    hote = hote if isinstance(hote, str) and _NOM.match(hote) else "un nom non servi"
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


def _sade(s: Sources, echeance: float) -> Optional[Dict[str, Any]]:
    """Propositions de SADE en attente (même règle que /defense/proposals : sans décision, ou à redécider)."""
    r = substrat.lire("actord", "/proposals", entetes={"X-Sbx-Vue": "complete"}, delai=DELAI_S, echeance=echeance)
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


def _sante(s: Sources, maintenant: float, admin: bool) -> Tuple[List[Dict[str, Any]], int]:
    """Services vitaux en échec et sites lents ou muets : seulement ce qu'une mesure fraîche dit. Leurs noms sont un
    inventaire : administrateur réel seulement, les autres lecteurs reçoivent des comptes. Rend aussi ce qui est tu."""
    out: List[Dict[str, Any]] = []
    tus = 0
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
        if pannes and not admin:
            out.append(_situation(
                "vitaux", "Services vitaux en échec", pl(len(pannes), "contrôle", "contrôles"), [["service en échec", "r"]], 85,
                f"{pl(len(pannes), 'contrôle échoue', 'contrôles échouent')} au dernier passage. Les noms sont réservés à l’administrateur.",
                faits=[{"ts": ts, "texte": pl(len(pannes), "contrôle en échec", "contrôles en échec"), "preuve": "contrôle de santé"}], poids=len(pannes),
                geste=_geste("Ouvrir la Santé", "/health/", "Le détail vit dans la page Santé.", "r")))
        tus = max(0, len(pannes) - VITAUX_MAX) if admin else 0
        for c in pannes[:VITAUX_MAX] if admin else []:
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
                        and isinstance(v.get("latency_ms"), (int, float)) and not isinstance(v.get("latency_ms"), bool) and 0 <= v["latency_ms"] < 1e7), key=lambda x: -x[1])
        # « down » compte aussi les refus voulus (401, 403, 404) : seuls un délai dépassé ou une erreur 5xx disent une panne
        muets = sorted(n for n, v in sites if v.get("status") == "down" and (v.get("error") == "timeout" or _n(v.get("status_code")) >= 500))
        if muets:
            out.append(_situation(
                "sites-muets", "Sites sans réponse", pl(len(muets), "site", "sites"), [["service en échec", "r"]], 82,
                f"{pl(len(muets), 'site ne répond', 'sites ne répondent')} pas ou {'rend' if len(muets) < 2 else 'rendent'} une erreur au dernier contrôle"
                + (f"\u00a0: {_liste_noms(muets)}." if admin else "."),
                faits=[{"ts": ts, "texte": n, "preuve": "contrôle de santé"} for n in muets[:LENTS_MAX]] if admin else
                [{"ts": ts, "texte": pl(len(muets), "site sans réponse", "sites sans réponse"), "preuve": "contrôle de santé"}], poids=len(muets),
                geste=_geste("Ouvrir la Santé", "/health/", "Le détail par site vit dans la page Santé.", "r")))
        if lents:
            out.append(_situation(
                "sites-lents", "Sites lents", pl(len(lents), "site", "sites"), [["service lent", "o"]], 55,
                f"{pl(len(lents), 'site dépasse', 'sites dépassent')} le seuil de réponse au dernier contrôle. Le plus lent "
                + (f"est {lents[0][0]}, à" if admin else "répond en") + f" {nb(round(lents[0][1]))} ms.",
                chaineTitre="Temps de réponse (ms)" if admin else None,
                chaine=[{"nom": n, "n": round(v), "cle": "passe"} for n, v in lents[:LENTS_MAX]] if admin else [],
                faits=[{"ts": ts, "texte": f"{n} : {nb(round(v))} ms", "preuve": "contrôle de santé"} for n, v in lents[:LENTS_MAX]] if admin else
                [{"ts": ts, "texte": f"Temps le plus long : {nb(round(lents[0][1]))} ms", "preuve": "contrôle de santé"}], poids=len(lents),
                geste=_geste("Ouvrir la Santé", "/health/", "Le détail par site vit dans la page Santé.")))
    return out, tus


def _liste_noms(noms: List[str], n: int = 3) -> str:
    vus = ", ".join(noms[:n])
    return vus if len(noms) <= n else f"{vus} et {pl(len(noms) - n, 'autre', 'autres')}"


def calculer(entetes: Dict[str, str], maintenant: float, admin: bool = False, echeance: Optional[float] = None) -> Dict[str, Any]:
    s, out = Sources(), []
    fin = time.monotonic() + ECHEANCE_S if echeance is None else echeance
    r = _lire_waf("/dossiers/sites", entetes, fin)
    sites = r["donnees"] if r["ok"] else None
    chiffrable = False
    if sites is not None and sites.get("disponible") is not True:
        s.dire("waf_sites", "WAF, relevé par site", "premier relevé en cours")
        sites = None
    elif sites is None:
        s.dire("waf_sites", "WAF, relevé par site", _motif(r))
    elif sites.get("perime") is True or sites.get("journal") == "illisible":
        s.dire("waf_sites", "WAF, relevé par site", "relevé figé")
        sites = None                    # un relevé figé n'est pas « les 24 dernières heures » ni « en ce moment »
    elif sites.get("rattrapage") is True or sites.get("complet") is False:
        s.dire("waf_sites", "WAF, relevé par site", "lecture en retard, chiffres suspendus")
    else:
        s.dire("waf_sites", "WAF, relevé par site")
        chiffrable = True
    dec = sites.get("decisions") if sites and isinstance(sites.get("decisions"), dict) else {}
    rot = dec.get("rotation") if isinstance(dec.get("rotation"), dict) else {}
    camps = {c["id"]: c for c in (rot.get("campagnes") if isinstance(rot.get("campagnes"), list) else [])
             if isinstance(c, dict) and isinstance(c.get("id"), str)}
    propose = rot.get("mode") == "propose" and rot.get("etat") == "ok"
    servies = {x for x in sites["cibles_servies"] if isinstance(x, str)} if sites and isinstance(sites.get("cibles_servies"), list) else None

    r = _lire_waf("/populations", entetes, fin)
    pops: List[Dict[str, Any]] = []
    if not r["ok"]:
        s.dire("waf_populations", "WAF, campagnes", _motif(r))
    elif r["donnees"].get("disponible") is not True or not isinstance(r["donnees"].get("populations"), list):
        s.dire("waf_populations", "WAF, campagnes", "aucun relevé")
    else:
        age = _entier(r["donnees"].get("age_s"))
        if age is None or age > POPULATIONS_FRAICHES_S:
            s.dire("waf_populations", "WAF, campagnes", "relevé figé")     # ni « depuis 24 h » ni « hier » sur un vieux relevé
        else:
            s.dire("waf_populations", "WAF, campagnes", "relevé partiel" if r["donnees"].get("complet") is False else None)
            releve = int(maintenant) - age
            pops = [x for x in (_population(p, camps, propose, servies, releve, maintenant) for p in r["donnees"]["populations"]
                                if isinstance(p, dict)) if x]
    pops.sort(key=lambda x: (-x["urgence"], -x["poids"]))
    out += pops[:POPULATIONS_MAX]
    couvertes = {x["id"].split(":", 1)[1] for x in pops}
    if propose:
        out += [x for x in (_rotation_seule(c) for i, c in camps.items() if i not in couvertes) if x]
    out += [x for x in (_candidats(k, dec.get(k)) for k in ("campagnes", "acteurs")) if x]

    attaques = [x for x in ((sites or {}).get("sites") or []) if isinstance(x, dict) and x.get("attaque") is True
                and isinstance(x.get("id"), str) and _NOM.match(x["id"]) and x["id"] != "noms-inconnus"] if chiffrable else []
    muet = False
    for x in attaques[:SITES_MAX]:
        d = {"ok": False, "erreur": "délai"} if muet else _lire_waf("/dossiers/sites/" + x["id"], entetes, fin)
        # un WAF qui ne répond plus : les suivants ne sont pas attendus ; un 404 (site sorti du relevé) ne dit rien des autres
        muet = muet or (not d["ok"] and not str(d.get("erreur") or "").startswith("http "))
        v = _site(d["donnees"] if d["ok"] and d["donnees"].get("disponible") is True else {**x, "phrase": "Site sous attaque. Le détail n’a pas pu être lu."})
        if v:
            out.append(v)
    sade = _sade(s, fin)
    if sade:
        out.append(sade)
    sante, vitaux_tus = _sante(s, maintenant, admin)
    out += sante
    out.sort(key=lambda x: (-x["urgence"], -x["poids"], x["titre"]))

    ch = sites.get("chiffres") if chiffrable and isinstance(sites.get("chiffres"), dict) else {}
    series = ch.get("series") if isinstance(ch.get("series"), dict) else {}
    decideurs = s.ok("waf_sites", "sade") and rot.get("tronque") is not True
    a_decider = sum(1 for x in out if ["à décider", "r"] in x["etiquettes"])
    complet = all(x["ok"] for x in s.l.values())
    autres = {"populations": max(0, len(pops) - POPULATIONS_MAX), "sites": max(0, len(attaques) - SITES_MAX), "vitaux": vitaux_tus}
    partiel = not complet or any(autres.values()) or rot.get("tronque") is True
    return {
        "genere_le": int(maintenant), "situations": out, "sources": list(s.l.values()), "complet": complet, "autres": autres,
        "chiffres": {
            # une source muette : le compte connu est un minimum annoncé ; sans rien de connu, null (jamais 0)
            "a_decider": a_decider if decideurs or a_decider else None, "a_decider_partiel": not decideurs,
            "en_cours": len(out) if not partiel or out else None, "en_cours_partiel": partiel,
            "ecartees_24h": _entier(ch.get("ecartees")), "passees_24h": _entier(ch.get("passees")),
            "series": {"ecartees": series.get("ecartees"), "passees": series.get("passees")},
            "heures_mesurees": _entier((sites or {}).get("heures_mesurees"))},
    }


# ── service : cache court par appelant, un calcul à la fois par clé, file bornée, échéance globale ───────────────

_CACHE: "OrderedDict[str, Tuple[float, Dict[str, Any]]]" = OrderedDict()
_EN_COURS: Dict[str, "Future[Dict[str, Any]]"] = {}
_VERROU = threading.Lock()
_FILS = ThreadPoolExecutor(max_workers=FILS, thread_name_prefix="situations")


class Occupe(Exception):
    """Trop de calculs en cours : la requête est refusée plutôt qu'empilée."""


def vider() -> None:
    with _VERROU:
        _CACHE.clear()


def _entetes(request: Request, payload: Any) -> Dict[str, str]:
    """Les seuls identifiants retransmis et mis en clé : porteur, cookie de SESSION (jamais les autres cookies), verdict LAN.
    Un tableau de bord sans session valable n'est connu que par le réseau local : ses jetons refusés ne font pas de clé."""
    e = defense._entetes_appelant(request)
    if isinstance(payload, dict) and payload.get("tableau_de_bord") is True:
        return {ENTETE_LAN: e[ENTETE_LAN]} if ENTETE_LAN in e else {}
    e.pop("Cookie", None)
    jeton = request.cookies.get(SESSION_COOKIE)
    if jeton:
        e["Cookie"] = f"{SESSION_COOKIE}={jeton}"
    return e


def _calcul(cle: str, entetes: Dict[str, str], admin: bool, depuis: float) -> Dict[str, Any]:
    p = calculer(entetes, time.time(), admin, depuis + ECHEANCE_S)
    with _VERROU:
        _CACHE.pop(cle, None)
        while len(_CACHE) >= CACHE_MAX:
            _CACHE.popitem(last=False)
        _CACHE[cle] = (time.monotonic(), p)
    return p


def _obtenir(entetes: Dict[str, str], admin: bool) -> Any:
    """Le résultat en cache, ou le calcul de cette clé (en cours, ou lancé ici). Lève `Occupe` si la file est pleine."""
    cle = hashlib.sha256((f"admin={admin}\0" + "\0".join(f"{k}={v}" for k, v in sorted(entetes.items()))).encode()).hexdigest()
    with _VERROU:
        e = _CACHE.get(cle)
        if e is not None and 0 <= time.monotonic() - e[0] < TTL_S:
            return e[1]
        for k in [k for k, f in _EN_COURS.items() if f.done()]:
            del _EN_COURS[k]
        f = _EN_COURS.get(cle)
        if f is None:
            if len(_EN_COURS) >= FILE_MAX:
                raise Occupe
            f = _EN_COURS[cle] = _FILS.submit(_calcul, cle, entetes, admin, time.monotonic())
        return f


@router.get("/situations")
async def situations(request: Request, payload: Any = Depends(require_lecture), admin: bool = Depends(defense._est_admin)):
    """Les situations, de la plus urgente à la plus calme, et l'état de lecture de chaque source."""
    try:
        p = _obtenir(_entetes(request, payload), admin)
        if isinstance(p, Future):
            p = await asyncio.wait_for(asyncio.shield(asyncio.wrap_future(p)), ATTENTE_S)
    except (Occupe, asyncio.TimeoutError):
        raise HTTPException(503, detail={"motif": "occupe"}, headers={"Retry-After": "15"}) from None
    return {**p, "age_s": max(0, int(time.time() - p["genere_le"]))}
