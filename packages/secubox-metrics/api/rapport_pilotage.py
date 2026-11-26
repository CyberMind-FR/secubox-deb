# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""
SecuBox-Deb :: metrics :: rapport de pilotage hebdomadaire (#3970)

Six feuilles A4 paysage, version papier de la charte Aurora, pour le client d'un relais : 1 synthèse (verdict + six chiffres avec
leur série et l'écart à la semaine précédente), 2 trafic par couches, 3 origines des requêtes hostiles, 4 défense, 5 acteurs suivis,
6 décisions et santé. Période : les 7 derniers jours complets de Paris (lundi à dimanche quand le rapport part le lundi).

Règles : données RÉELLES seulement (les lecteurs de `releve_quotidien`) ; une mesure absente est « non mesuré », jamais 0 ni
estimée ; un chiffre de la semaine n'est écrit que si ses 7 jours sont mesurés, et l'écart seulement si la semaine précédente
l'est aussi ; verdict, phrases et décisions sont construits par le code à partir des seuils écrits ci-dessous (aucune IA, aucune
décision inventée : s'il n'y a rien à décider, la feuille le dit) ; aucune adresse IP ni identifiant d'acteur ne sort (acteurs
nommés A, B, C… ; tout texte passe par `sans_ip`). Police de base de fpdf (latin-1), translittérée comme pdf_aurora.

Usage : `python3 -m api.rapport_pilotage` (minuterie, envoi seulement si `[rapport.pilotage] actif = true`) ;
`--sortie fichier.pdf` génère sans envoyer ; `--fin AAAA-MM-JJ` choisit le dernier jour ; `--exemple` prend un jeu fictif annoncé.
"""
from __future__ import annotations

import math
import random
import sys
import time
import tomllib
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from statistics import median
from typing import Any, Callable, Optional

_ici = str(Path(__file__).resolve().parent)
if _ici not in sys.path:
    sys.path.insert(0, _ici)

import releve_quotidien as RQ  # noqa: E402
from releve_quotidien import PARIS, sans_ip  # noqa: E402

CONF = Path("/etc/secubox/metrics.toml")
DEFAUTS = {"actif": False, "destinataire": "", "noeud": ""}

# ── seuils écrits (chaque décision et chaque phrase en découle ; testés) ──
SEUIL_ATTENTE = 1                 # adresses proposées au ban, sans ban depuis : une décision dès la première
SEUIL_DISPO = 99.5                # disponibilité de la semaine sous ce taux : comprendre les interruptions
SEUIL_LENT_MS = 500.0             # temps de réponse médian au-dessus (même seuil que la sonde « slow ») : examiner
SEUIL_SITE_PART = 0.5             # un site qui reçoit au moins la moitié des requêtes bloquées…
SEUIL_SITE_MIN = 1000             # … et au moins 1 000 sur la semaine : revoir son exposition
SEUIL_PIC_FACTEUR = 3.0           # un jour à 3 fois la médiane des autres…
SEUIL_PIC_MIN = 500               # … et au moins 500 requêtes bloquées : un pic, annoncé
DECISIONS_MAX = 3

# ── palette papier (validée sur la maquette) ──────────────────────────────
BLANC, CREUX, TRAIT = (255, 255, 255), (243, 246, 251), (213, 222, 236)
TEXTE, DOUX = (16, 32, 58), (72, 89, 122)
C1, C2, C3, C4, OK = (31, 111, 208), (176, 122, 0), (124, 77, 219), (207, 47, 58), (19, 122, 69)

JOURS_COURTS = ("lun.", "mar.", "mer.", "jeu.", "ven.", "sam.", "dim.")
MOIS = ("janvier", "février", "mars", "avril", "mai", "juin", "juillet", "août", "septembre", "octobre", "novembre", "décembre")
PAYS_FR = {"AD": "Andorre", "AE": "Émirats arabes unis", "AL": "Albanie", "AM": "Arménie", "AR": "Argentine", "AT": "Autriche",
           "AU": "Australie", "AZ": "Azerbaïdjan", "BA": "Bosnie", "BD": "Bangladesh", "BE": "Belgique", "BG": "Bulgarie", "BR": "Brésil",
           "BY": "Biélorussie", "CA": "Canada", "CH": "Suisse", "CL": "Chili", "CN": "Chine", "CO": "Colombie", "CZ": "Tchéquie",
           "DE": "Allemagne", "DK": "Danemark", "DZ": "Algérie", "EC": "Équateur", "EE": "Estonie", "EG": "Égypte", "ES": "Espagne",
           "FI": "Finlande", "FR": "France", "GB": "Royaume-Uni", "GE": "Géorgie", "GR": "Grèce", "HK": "Hong Kong", "HR": "Croatie",
           "HU": "Hongrie", "ID": "Indonésie", "IE": "Irlande", "IL": "Israël", "IN": "Inde", "IQ": "Irak", "IR": "Iran", "IS": "Islande",
           "IT": "Italie", "JP": "Japon", "KE": "Kenya", "KG": "Kirghizistan", "KR": "Corée du Sud", "KZ": "Kazakhstan", "LT": "Lituanie",
           "LU": "Luxembourg", "LV": "Lettonie", "MA": "Maroc", "MD": "Moldavie", "MX": "Mexique", "MY": "Malaisie", "NG": "Nigeria",
           "NL": "Pays-Bas", "NO": "Norvège", "NZ": "Nouvelle-Zélande", "PE": "Pérou", "PH": "Philippines", "PK": "Pakistan",
           "PL": "Pologne", "PT": "Portugal", "RO": "Roumanie", "RS": "Serbie", "RU": "Russie", "SA": "Arabie saoudite", "SE": "Suède",
           "SG": "Singapour", "SI": "Slovénie", "SK": "Slovaquie", "TH": "Thaïlande", "TN": "Tunisie", "TR": "Turquie", "TW": "Taïwan",
           "UA": "Ukraine", "US": "États-Unis", "UZ": "Ouzbékistan", "VE": "Venezuela", "VN": "Viêt Nam", "ZA": "Afrique du Sud",
           "autres": "Autres pays"}
# Noms des catégories du WAF, comme les pages web (table CATEGORIES de composants/waf/api/dossiers.py, secubox-waf-ng ; recopiée :
# un autre paquet). Une catégorie inconnue garde son nom brut, nettoyé.
CATEGORIES_FR = {
    "sqli": "Injection SQL", "xss": "Script injecté", "lfi": "Lecture de fichiers interdits", "rce": "Exécution de code",
    "cve_2024": "Failles connues", "scanners": "Outils de balayage", "webmail": "Attaque du webmail",
    "api_abuse": "Abus d'API", "voip": "Attaque de la téléphonie", "xmpp": "Attaque de la messagerie instantanée",
    "cve_voip": "Failles de téléphonie", "cve_xmpp": "Failles de messagerie instantanée",
    "router_botnet": "Robots de prise de contrôle", "waf_fingerprint": "Sonde du pare-feu", "honeypot": "Pièges touchés",
    "recon_crawler": "Exploration", "credential_harvest": "Recherche de mots de passe",
    "product_absent_probes": "Logiciels absents d'ici", "roundcube": "Failles de Roundcube",
    "nextcloud": "Failles de Nextcloud", "php_requete": "Requêtes PHP anormales", "aspirateur_ua": "Outil d'aspiration",
    "php2shell": "Envoi de code PHP", "leurre_redirige": "Détournées vers un leurre", "robots": "Robots",
    "rotation": "Adresses tournantes", "host_anomaly:unrouted": "Noms non servis", "host_anomaly:empty": "Nom absent",
    "host_anomaly:ip_literal": "Accès par adresse IP", "host_anomaly:dga": "Nom fabriqué", "autres": "Autres motifs",
    "auth_smtp": "Mots de passe sur la messagerie", "auth_imap": "Mots de passe sur la messagerie",
    "auth_ssh": "Mots de passe SSH", "leurre_ssh": "Leurre SSH touché", "leurre_smtp": "Leurre de messagerie touché",
}


def libelle_categorie(cat: Any) -> str:
    """Nom français d'une catégorie du WAF : exact, puis sans le suffixe « |… », puis le préfixe avant « : »."""
    c = str(cat or "?").split("|", 1)[0]
    if c in CATEGORIES_FR:
        return CATEGORIES_FR[c]
    base = c.split(":", 1)[0]
    if base in CATEGORIES_FR:
        return CATEGORIES_FR[base]
    if base.startswith("leurre"):
        return "Leurre touché"
    return c.replace("_", " ")


NIVEAU_FR = {"BLOCK": "Bloquer", "MITIGATE": "Freiner", "OBSERVE": "Observer"}
MESURE_FR = {"DELAY": "Ralenti", "CHALLENGE": "Défi", "TARPIT": "Englué", "DENY": "Refusé", "QUARANTINE": "Quarantaine", "OBSERVE": "Observé"}
FAMILLE_FR = {"collecte": "Collecte", "messagerie": "Messagerie", "acces_distant": "Accès distant", "balayage_web": "Balayage web"}
NON_MESURE = "non mesuré"


# ── formats français ──────────────────────────────────────────────────────
def pl(n: float, sing: str, plur: str) -> str:
    """Accord : singulier pour 0 et 1 (règle française), pluriel au-delà."""
    return sing if abs(n) < 2 else plur


def fn(v: Optional[float]) -> str:
    if v is None:
        return NON_MESURE
    return f"{int(round(v)):,}".replace(",", " ")


def fd(v: Optional[float], d: int = 1) -> str:
    if v is None:
        return NON_MESURE
    return f"{v:,.{d}f}".replace(",", " ").replace(".", ",")


def fpct(v: Optional[float], d: int = 1) -> str:
    return NON_MESURE if v is None else fd(v, d) + " %"


def compte(n: Optional[float], sing: str, plur: str) -> str:
    return NON_MESURE if n is None else f"{fn(n)} {pl(n, sing, plur)}"


def jour_court(j: str) -> str:
    d = date.fromisoformat(j)
    return f"{JOURS_COURTS[d.weekday()]} {d.day}"


def date_longue(j: str) -> str:
    d = date.fromisoformat(j)
    return f"{d.day}{'er' if d.day == 1 else ''} {MOIS[d.month - 1]} {d.year}"


def libelle_periode(jours: list[str]) -> str:
    a, b = date.fromisoformat(jours[0]), date.fromisoformat(jours[-1])
    if a.month == b.month:
        return f"du {a.day}{'er' if a.day == 1 else ''} au {date_longue(jours[-1])}"
    return f"du {a.day}{'er' if a.day == 1 else ''} {MOIS[a.month - 1]} au {date_longue(jours[-1])}"


def heure_paris(ts: Optional[float]) -> str:
    return "" if ts is None else datetime.fromtimestamp(ts, PARIS).strftime("%d/%m %H:%M")


# ── période ───────────────────────────────────────────────────────────────
def periode(fin: str) -> tuple[list[str], list[str]]:
    """Les 7 jours qui finissent `fin` (compris) et les 7 qui précèdent."""
    f = date.fromisoformat(fin)
    cur = [(f - timedelta(days=6 - i)).isoformat() for i in range(7)]
    prec = [(f - timedelta(days=13 - i)).isoformat() for i in range(7)]
    return cur, prec


# ── séries et chiffres de la semaine (fonctions pures) ───────────────────
def serie(data: dict, jours: list[str], extraire: Callable[[dict], Optional[float]]) -> list[Optional[float]]:
    out = []
    for j in jours:
        r = (data.get("par_jour") or {}).get(j) or {}
        try:
            v = extraire(r)
        except (TypeError, KeyError, AttributeError):
            v = None
        out.append(None if v is None else float(v))
    return out


def mesures(s: list[Optional[float]]) -> int:
    return sum(v is not None for v in s)


def somme(s: list[Optional[float]]) -> Optional[float]:
    """La somme de la semaine, seulement si ses 7 jours sont mesurés."""
    return sum(s) if s and all(v is not None for v in s) else None


def moyenne(s: list[Optional[float]]) -> Optional[float]:
    return sum(s) / len(s) if s and all(v is not None for v in s) else None


def mediane(s: list[Optional[float]]) -> Optional[float]:
    return float(median(s)) if s and all(v is not None for v in s) else None


def ecart(cur: Optional[float], prec: Optional[float], genre: str) -> Optional[tuple[str, int]]:
    """Texte et sens (+1 hausse, -1 baisse, 0 stable) de l'écart ; None si l'une des deux semaines n'est pas mesurée.
    genre : « compte » (en %), « points » (pourcentage, en points), « ms »."""
    if cur is None or prec is None:
        return None
    d = cur - prec
    if genre == "points":
        if abs(d) < 0.005:
            return "stable", 0
        return f"{'+' if d > 0 else '-'}{fd(abs(d), 2)} {pl(round(abs(d), 2), 'point', 'points')}", 1 if d > 0 else -1
    if genre == "ms":
        if abs(d) < 0.5:
            return "stable", 0
        return f"{'+' if d > 0 else '-'}{fn(abs(d))} ms", 1 if d > 0 else -1
    if prec == 0:
        return ("stable", 0) if cur == 0 else ("nouveau : 0 la semaine précédente", 1)
    p = 100.0 * d / prec
    if abs(p) < 0.05:
        return "stable", 0
    return f"{'+' if p > 0 else '-'}{fd(abs(p), 1)} %", 1 if p > 0 else -1


def _v(r: dict, *cles):
    x: Any = r
    for c in cles:
        if not isinstance(x, dict):
            return None
        x = x.get(c)
    return x


def kpis(data: dict) -> list[dict]:
    """Les six chiffres de la synthèse : valeur de la semaine, série par jour, écart, sens d'une hausse (+1 bon, -1 mauvais, 0 neutre)."""
    cur, prec = data["jours"], data["precedents"]
    defs = [
        ("dispo", "Disponibilité", lambda r: r.get("dispo"), moyenne, "points", +1, C1, lambda v: fpct(v, 2), "part des relevés de Status Live au vert"),
        ("servies", "Requêtes servies", lambda r: _v(r, "nginx", "requetes"), somme, "compte", +1, C1, fn, "journaux nginx, tous sites"),
        ("latence", "Temps de réponse médian", lambda r: _v(r, "latence", "mediane_ms"), mediane, "ms", -1, C2,
         lambda v: NON_MESURE if v is None else f"{fn(v)} ms", "sonde de santé, un relevé par jour"),
        ("bloquees", "Requêtes bloquées", lambda r: _v(r, "waf", "bloquees"), somme, "compte", 0, C4, fn, "arrêtées, refusées ou détournées par le WAF"),
        ("bans", "Bans posés", lambda r: _v(r, "bans", "bans"), somme, "compte", 0, C4, fn, "adresses mises au ban, hors prolongations"),
        ("dns", "Requêtes DNS filtrées", lambda r: _v(r, "dns", "filtrees"), somme, "compte", 0, C3, fn, "filtrage DNS, jours UTC"),
    ]
    out = []
    for cle, lib, ext, agg, genre, sens, coul, fmt, definition in defs:
        s, sp = serie(data, cur, ext), serie(data, prec, ext)
        v, vp = agg(s), agg(sp)
        e = ecart(v, vp, genre)
        k = mesures(s)
        if v is not None:
            sous = (f"{e[0]} sur la semaine précédente" if e else "sans comparaison (semaine préc. non mesurée)")
        else:
            sous = f"mesuré {k} {pl(k, 'jour', 'jours')} sur 7" if k else "aucun jour mesuré"
            if cle == "latence" and _v(data, "instant", "latence", "mediane_ms") is not None:
                sous = f"instantané : {fn(data['instant']['latence']['mediane_ms'])} ms le {heure_paris(data['instant']['latence'].get('instant'))}"
        out.append({"cle": cle, "libelle": lib, "valeur": v, "texte": fmt(v), "serie": s, "precedent": vp, "ecart": e, "sens": sens,
                    "couleur": coul, "sous": sous, "definition": definition, "jours_mesures": k})
    return out


def couches(data: dict) -> dict:
    """Trafic par couche et par jour. Couches exclusives : visiteurs et robots déclarés (nginx, après le WAF), détournées vers un
    leurre et bloquées (WAF, jamais servies)."""
    cur = data["jours"]
    c = {
        "Visiteurs": serie(data, cur, lambda r: None if r.get("nginx") is None else max(0, r["nginx"]["requetes"] - r["nginx"]["robots"])),
        "Robots déclarés": serie(data, cur, lambda r: _v(r, "nginx", "robots")),
        "Détournées (leurres)": serie(data, cur, lambda r: _v(r, "waf", "couches", "detourne")),
        "Bloquées": serie(data, cur, lambda r: None if r.get("waf") is None else r["waf"]["couches"]["arrete"] + r["waf"]["couches"]["refuse"]),
    }
    return c


def parts(cs: dict) -> list[tuple[str, Optional[float], str]]:
    """Part de chaque couche sur la semaine, avec son texte. Toutes les couches complètes : la part en %. Sinon, une couche complète
    donne son total, une couche incomplète dit sur combien de jours elle n'est pas mesurée (jamais une part sur un total partiel)."""
    tot = {k: somme(v) for k, v in cs.items()}
    if all(v is not None for v in tot.values()) and sum(tot.values()):
        t = sum(tot.values())
        return [(k, 100.0 * v / t, fpct(100.0 * v / t, 1)) for k, v in tot.items()]
    out = []
    for k, v in cs.items():
        manque = 7 - mesures(v)
        if tot[k] is not None:
            out.append((k, None, fn(tot[k])))
        else:
            out.append((k, None, f"{NON_MESURE} sur {manque} {pl(manque, 'jour', 'jours')}"))
    return out


def pic(s: list[Optional[float]], jours: list[str]) -> Optional[dict]:
    """Le jour qui dépasse SEUIL_PIC_FACTEUR fois la médiane des autres jours mesurés et SEUIL_PIC_MIN ; None sinon."""
    vals = [(j, v) for j, v in zip(jours, s) if v is not None]
    if len(vals) < 3:
        return None
    j, v = max(vals, key=lambda x: x[1])
    autres = [x for jj, x in vals if jj != j]
    m = median(autres)
    if v >= SEUIL_PIC_MIN and v >= SEUIL_PIC_FACTEUR * max(m, 1):
        return {"jour": j, "valeur": v, "facteur": v / max(m, 1)}
    return None


def cumul_dict(data: dict, jours: list[str], chemin: tuple) -> tuple[dict, int]:
    """Somme des dictionnaires {clé: n} des jours mesurés ; rend aussi le nombre de jours mesurés."""
    tot: dict = {}
    k = 0
    for j in jours:
        d = _v((data.get("par_jour") or {}).get(j) or {}, *chemin)
        if not isinstance(d, dict):
            continue
        k += 1
        for c, n in d.items():
            tot[c] = tot.get(c, 0) + (n if isinstance(n, (int, float)) else 0)
    return tot, k


def pays(data: dict) -> tuple[list[dict], int]:
    """Pays des requêtes hostiles des jours mesurés : requêtes hostiles, bloquées, part bloquée."""
    tot: dict = {}
    k = 0
    for j in data["jours"]:
        d = _v((data.get("par_jour") or {}).get(j) or {}, "waf", "pays")
        if not isinstance(d, dict):
            continue
        k += 1
        for cc, hb in d.items():
            if isinstance(hb, (list, tuple)) and len(hb) == 2:
                t = tot.setdefault(cc, [0, 0])
                t[0] += hb[0]
                t[1] += hb[1]
    out = [{"code": cc, "nom": PAYS_FR.get(cc, cc), "hostiles": h, "bloquees": b, "part": (100.0 * b / h) if h else None}
           for cc, (h, b) in tot.items()]
    return sorted(out, key=lambda p: (-p["bloquees"], -p["hostiles"], p["code"])), k


def chaleur(data: dict) -> list[Optional[list[int]]]:
    """Requêtes bloquées par jour (ligne) et heure de Paris (colonne) ; None pour un jour non mesuré."""
    return [(_v((data.get("par_jour") or {}).get(j) or {}, "waf", "heures") or None) if _v((data.get("par_jour") or {}).get(j) or {}, "waf") else None
            for j in data["jours"]]


def absentes(data: dict) -> list[str]:
    """Les mesures manquantes de la semaine, dites telles quelles."""
    noms = (("waf", "journal des menaces du WAF"), ("bans", "journal des bans"), ("nginx", "requêtes servies (nginx)"),
            ("dispo", "disponibilité (Status Live)"), ("latence", "temps de réponse (relevé quotidien)"), ("dns", "filtrage DNS"))
    out = []
    for cle, lib in noms:
        k = mesures(serie(data, data["jours"], lambda r, c=cle: None if r.get(c) is None else 1))
        if k < 7:
            out.append(f"{lib} : {NON_MESURE}" if k == 0 else f"{lib} : {k} {pl(k, 'jour', 'jours')} sur 7")
    inst = data.get("instant") or {}
    if inst.get("acteurs") is None:
        out.append(f"acteurs suivis (Actor Intelligence) : {NON_MESURE}")
    if inst.get("sante") is None:
        out.append(f"contrôles de santé : {NON_MESURE}")
    return out


# ── décisions (règles écrites, jamais inventées) ──────────────────────────
def lettre(i: int) -> str:
    return "Acteur " + chr(ord("A") + i) if i < 26 else f"Acteur {i + 1}"


def decisions(data: dict, ks: Optional[list[dict]] = None) -> list[dict]:
    """Au plus DECISIONS_MAX décisions, par ordre d'urgence, chacune née d'un seuil franchi par une mesure réelle."""
    ks = ks or kpis(data)
    K = {k["cle"]: k for k in ks}
    inst = data.get("instant") or {}
    out: list[dict] = []
    sante = inst.get("sante")
    if sante and sante.get("vitaux_ko"):
        n = len(sante["vitaux_ko"])
        noms = ", ".join(f"« {x} »" for x in sante["vitaux_ko"][:3])
        out.append({"regle": "service_vital", "horizon": "Cette semaine",
                    "titre": f"Remettre en service {pl(n, 'le contrôle', 'les contrôles')} {noms}",
                    "raison": f"{n} {pl(n, 'contrôle vital échoue', 'contrôles vitaux échouent')} au relevé de santé du {heure_paris(sante.get('instant'))}.",
                    "effet": f"{pl(n, 'Le contrôle repasse', 'Les contrôles repassent')} au vert ; le service gardé redevient joignable."})
    lat = inst.get("latence")
    if lat and lat.get("injoignables"):
        n = len(lat["injoignables"])
        out.append({"regle": "site_injoignable", "horizon": "Cette semaine",
                    "titre": f"Rétablir {n} {pl(n, 'site injoignable', 'sites injoignables')}",
                    "raison": f"{pl(n, 'Il ne répond', 'Ils ne répondent')} plus à la sonde de santé ({heure_paris(lat.get('instant'))}) : "
                              + ", ".join(lat["injoignables"][:10]) + ".",
                    "effet": f"{pl(n, 'Le site répond', 'Les sites répondent')} de nouveau à la sonde."})
    att = inst.get("attente")
    if att and (att.get("en_attente") or 0) >= SEUIL_ATTENTE:
        n = att["en_attente"]
        out.append({"regle": "ban_en_attente", "horizon": "Cette semaine",
                    "titre": f"Valider ou écarter {n} {pl(n, 'adresse proposée', 'adresses proposées')} au ban",
                    "raison": f"Le WAF {pl(n, 'l’a proposée', 'les a proposées')} sur les 7 derniers jours ; aucun ban n'a suivi. En mode proposition, rien n'est appliqué sans vous.",
                    "effet": f"{pl(n, 'Cette adresse ne joint', 'Ces adresses ne joignent')} plus aucun service ; un ban se lève à tout moment."})
    act = inst.get("acteurs")
    if act:
        for i, a in enumerate(act.get("acteurs") or []):
            if a.get("niveau") == "BLOCK" and not a.get("mesure"):
                na = a.get("adresses")
                out.append({"regle": "acteur_a_bloquer", "horizon": "Cette semaine", "titre": f"Décider du blocage de l'acteur {lettre(i).split()[-1]}",
                            "raison": f"Risque {fn(a.get('risque'))} sur 100, blocage proposé par Actor Intelligence et aucune mesure en cours"
                                      + (f" ; {compte(na, 'adresse connue', 'adresses connues')}." if na is not None else "."),
                            "effet": "Ses adresses ne joignent plus les services ; la décision reste réversible."})
                break
    d = K["dispo"]["valeur"]
    if d is not None and d < SEUIL_DISPO:
        out.append({"regle": "dispo", "horizon": "Ce mois", "titre": "Comprendre les interruptions de service",
                    "raison": f"Disponibilité de la semaine : {fpct(d, 2)}, sous le seuil de {fpct(SEUIL_DISPO, 1)}.",
                    "effet": f"Le service tient au-dessus de {fpct(SEUIL_DISPO, 1)} de disponibilité."})
    m = K["latence"]["valeur"]
    if m is None and lat:
        m = lat.get("mediane_ms")
    if m is not None and m > SEUIL_LENT_MS:
        lent = (lat or {}).get("lents") or []
        cible = f" ({lent[0][0]} le plus lent)" if lent else ""
        out.append({"regle": "latence", "horizon": "Ce mois", "titre": f"Examiner le temps de réponse{cible}",
                    "raison": f"Temps de réponse médian : {fn(m)} ms, au-dessus de {fn(SEUIL_LENT_MS)} ms.",
                    "effet": f"Le temps de réponse médian revient sous {fn(SEUIL_LENT_MS)} ms."})
    sites, k = cumul_dict(data, data["jours"], ("waf", "sites_bloques"))
    tot = K["bloquees"]["valeur"]
    if tot and sites and k == 7:
        s, n = max(sites.items(), key=lambda kv: kv[1])
        if n >= SEUIL_SITE_MIN and n >= SEUIL_SITE_PART * tot and s not in ("autres", "(sans nom)", "(adresse IP nue)"):
            out.append({"regle": "site_sous_attaque", "horizon": "Ce mois", "titre": f"Revoir l'exposition de {s}",
                        "raison": f"Ce site reçoit {fpct(100.0 * n / tot, 0)} des requêtes bloquées de la semaine ({fn(n)}).",
                        "effet": "Moins de surface exposée : seul ce qui doit être public le reste."})
    if mesures(K["bloquees"]["serie"]) == 0:
        out.append({"regle": "mesure_absente", "horizon": "À prévoir", "titre": "Rendre lisible le journal des menaces du WAF",
                    "raison": "Aucun jour de la semaine n'a pu être mesuré : le rapport ne peut rien dire de la défense.",
                    "effet": "Le prochain rapport chiffre aussi les requêtes bloquées."})
    return out[:DECISIONS_MAX]


def verdict(data: dict, ks: list[dict], decs: list[dict]) -> str:
    """Le titre de la synthèse, fait des mesures de la semaine (jamais d'une estimation)."""
    K = {k["cle"]: k for k in ks}
    phrases = {"dispo": lambda v: f"Service disponible à {fpct(v, 2)}",
               "servies": lambda v: f"{fn(v)} {pl(v, 'requête servie', 'requêtes servies')}",
               "bloquees": lambda v: f"{fn(v)} {pl(v, 'requête hostile arrêtée', 'requêtes hostiles arrêtées')}",
               "bans": lambda v: f"{fn(v)} {pl(v, 'adresse mise au ban', 'adresses mises au ban')}",
               "dns": lambda v: f"{fn(v)} {pl(v, 'requête DNS filtrée', 'requêtes DNS filtrées')}"}
    # Ce qui est mesuré d'abord, deux chiffres au plus ; ce qui manque va dans le sous-titre (`manques`).
    bouts = [f(K[c]["valeur"]) for c, f in phrases.items() if K[c]["valeur"] is not None][:2]
    if not bouts:
        bouts.append("Semaine incomplètement mesurée")
    n = len(decs)
    fin = f"{n} {pl(n, 'décision', 'décisions')} à prendre" if n else "rien à décider"
    t = ", ".join(bouts) + f" ; {fin}"
    return t[0].upper() + t[1:]


def manques(ks: list[dict]) -> str:
    """Le sous-titre des chiffres non mesurés de la semaine (vide si tout est mesuré)."""
    m = [k["libelle"].lower() for k in ks if k["valeur"] is None]
    return ("Non mesuré cette semaine : " + ", ".join(m) + ".") if m else ""


# ── collecte ──────────────────────────────────────────────────────────────
CLES_JOUR = ("waf", "bans", "dns", "nginx", "dispo", "latence")


def fusionner(vivant: dict, releves: dict, jours: list[str]) -> dict:
    """Par jour et par source : la source vivante si elle mesure le jour, sinon le relevé quotidien de ce jour, sinon rien."""
    out = {}
    for j in jours:
        v = vivant.get(j) or {}
        r = releves.get(j) or {}
        out[j] = {"jour": j, **{c: (v.get(c) if v.get(c) is not None else r.get(c)) for c in CLES_JOUR}}
    return out


def collecter(fin: str, maintenant: Optional[float] = None, dossier: Optional[Path] = None, noeud: str = "") -> dict:
    maintenant = time.time() if maintenant is None else maintenant
    cur, prec = periode(fin)
    tous = prec + cur
    sources = {}
    if noeud:
        sources["dispo"] = RQ.lire_dispo(jours=tous, noeud=noeud)
    c = RQ.collecter_jours(tous, maintenant, sources=sources)
    rel = RQ.lire_releves(dossier or RQ.dossier_releves(), tous)
    bb = c.get("bans_brut") or {}
    return {"jours": cur, "precedents": prec, "par_jour": fusionner(c["jours"], rel, tous), "genere": maintenant, "exemple": False,
            "instant": {"latence": RQ.latence_confirmee(maintenant=maintenant), "sante": RQ.lire_sante(maintenant=maintenant),
                        "acteurs": RQ.lire_acteurs(), "populations": RQ.lire_populations(),
                        "attente": RQ.lire_attente(dernier_ban=bb.get("dernier_ban"), depuis=maintenant - 7 * 86400)}}


def donnees_exemple(fin: str = "2026-11-22", graine: int = 7) -> dict:
    """Jeu FICTIF, annoncé comme tel sur chaque feuille (« Données d'exemple ») : sert à l'exemple livré et aux tests."""
    g = random.Random(graine)
    cur, prec = periode(fin)
    par_jour = {}
    for i, j in enumerate(prec + cur):
        vague = 1.9 if j == cur[3] else 1.0
        bl = int(2600 * (0.8 + 0.4 * g.random()) * vague)
        cats = {"failles connues": int(bl * .36), "force brute": int(bl * .24), "aspirateurs": int(bl * .19), "chemins leurres": int(bl * .14)}
        cats["formulaires"] = bl - sum(cats.values())
        h = [max(0, int(bl / 24 * (1.6 if x < 6 else 1.2 if x > 20 else .75) * (0.7 + 0.6 * g.random()))) for x in range(24)]
        req = int(30000 * (0.85 + 0.3 * g.random()) * (0.75 if date.fromisoformat(j).weekday() > 4 else 1))
        rob = int(req * (0.28 + 0.06 * g.random()))
        par_jour[j] = {
            "jour": j, "dispo": 99.71 if j == cur[3] else round(99.95 + 0.05 * g.random(), 3),
            "latence": {"mediane_ms": float(int(84 + 26 * g.random() + (70 if j == cur[3] else 0))), "sites": 6, "lents": [], "injoignables": []} if i >= 4 else None,
            "nginx": {"requetes": req, "visites": int(req * .4), "robots": rob, "sondes": int(req * .03), "erreurs": int(req * .02),
                      "par_site": {"www.exemple.test": int(req * .38), "mail.exemple.test": int(req * .24), "git.exemple.test": int(req * .17),
                                   "video.exemple.test": int(req * .14), "agenda.exemple.test": int(req * .07)}},
            "waf": {"couches": {"arrete": int(bl * .55), "refuse": int(bl * .30), "detourne": bl - int(bl * .55) - int(bl * .30),
                                "passe": int(bl * .4), "robots": int(rob * .5)},
                    "bloquees": bl, "hostiles": int(bl * 1.4), "categories": cats, "heures": h,
                    "sites_bloques": {"www.exemple.test": int(bl * .45), "mail.exemple.test": int(bl * .3), "git.exemple.test": bl - int(bl * .45) - int(bl * .3)},
                    "sites_hostiles": {"www.exemple.test": int(bl * .6)},
                    "pays": {cc: [int(bl * 1.4 * p), int(bl * 1.4 * p * q)] for cc, p, q in
                             (("US", .22, .78), ("CN", .12, .86), ("DE", .10, .64), ("FR", .18, .21), ("BR", .07, .81), ("IN", .06, .74),
                              ("SG", .05, .9), ("RU", .05, .83), ("NL", .05, .52))}},
            "bans": {"bans": int(bl / 46), "adresses": int(bl / 50), "prolongations": int(bl / 200)},
            "dns": {"requetes": 90000, "filtrees": int(5200 + 1900 * g.random()), "domaines": int(800 + 200 * g.random())},
        }

    def jours_act(base):
        return {"debut": 0, "pas": 86400, "valeurs": [int(base * (0.3 + g.random())) for _ in range(15)], "dates": cur}
    acteurs = [{"id": f"ACT-{i:04d}", "niveau": n, "action": n, "scenario": s, "risque": r, "confiance": c, "evenements": e,
                "mesure": m, "adresses": a, "bans": b, "tags": [], "jours": jours_act(e / 7)}
               for i, (n, s, r, c, e, m, a, b) in enumerate((
                   ("BLOCK", "Sondes de failles", 94, 88, 18400, {"niveau": "DENY", "reste_s": 5 * 86400}, 212, 180),
                   ("BLOCK", "Aspirateur à rotation d'adresses", 91, 80, 15200, None, 640, 12),
                   ("MITIGATE", "Force brute messagerie", 72, 70, 9100, {"niveau": "TARPIT", "reste_s": 20 * 3600}, 38, 30),
                   ("MITIGATE", "Chemins leurres", 64, 66, 5300, {"niveau": "DENY", "reste_s": 10 * 3600}, 21, 19),
                   ("OBSERVE", "Robot non déclaré", 41, 55, 3900, {"niveau": "DELAY", "reste_s": 3600}, 12, 0),
                   ("OBSERVE", "Balayage de ports", 30, 40, 1200, None, 7, 0)))]
    pops = [{"famille": f, "nom_cible": t, "adresses": a, "rotation": r, "etat": e, "serie": [int(a * (0.5 + g.random())) for _ in range(7)],
             "pays_top": [["US", 34], ["CN", 21], ["NL", 9]] if f == "balayage_web" else [["RU", 40], ["BR", 22], ["IN", 15]]}
            for f, t, a, r, e in (("balayage_web", "www.exemple.test", 1320, True, "observee"), ("messagerie", "mail.exemple.test", 410, False, "bannie"),
                                  ("acces_distant", "ssh", 95, True, "observee"), ("collecte", "git.exemple.test", 60, False, "inactive"))]
    t = datetime.fromisoformat(fin + "T23:00:00+01:00").timestamp() + 7 * 3600
    return {"jours": cur, "precedents": prec, "par_jour": par_jour, "genere": t, "exemple": True,
            "instant": {"latence": {"mediane_ms": 96.0, "sites": 6, "lents": [], "injoignables": [], "instant": t},
                        "sante": {"total": 10, "ok": 9, "vitaux_ko": [], "avertissements": ["comptes-admin"], "instant": t},
                        "acteurs": {"suivis": 27, "a_bloquer": 1, "acteurs": acteurs, "genere_le": t},
                        "populations": {"genere_le": t, "populations": pops},
                        "attente": {"en_attente": 14, "proposees": 31, "plus_ancienne": t - 3 * 86400}}}


# ── emojis : petites images (police couleur Noto, rendue par Pillow) ─────
# La police de base de fpdf ne connaît que latin-1 et la police couleur Noto (CBDT) ne s'insère pas comme texte : chaque emoji est
# rendu une fois en PNG (taille native 109 de la police) puis posé comme image. Police ou Pillow absents : pas d'icône, rien d'autre.
EMOJI_POLICE = Path("/usr/share/fonts/truetype/noto/NotoColorEmoji.ttf")
_EMOJIS: dict = {}
ICONES_KPI = {"dispo": "✅", "servies": "🌐", "latence": "⏱️", "bloquees": "🛡️", "bans": "🚫", "dns": "🔎"}
ICONES_COUCHE = {"Visiteurs": "👤", "Robots déclarés": "🤖", "Détournées (leurres)": "🎯", "Bloquées": "🚫",
                 "Arrêtées (adresse au ban)": "⛔", "Refusées": "🚫", "Détournées vers un leurre": "🎯", "Laissées passer, surveillées": "👁️",
                 "Requêtes reçues": "🌐", "Requêtes hostiles reconnues": "⚠️", "Requêtes bloquées": "🛡️", "Bans posés": "⛔"}
ICONES_ETAT = {"À décider": "⚠️", "Observé": "👁️", "Ralenti": "🐢", "Défi": "🧩", "Englué": "🕸️", "Refusé": "🚫", "Quarantaine": "🔒"}
_ICONES_CAT = (("brute", "🔑"), ("mot de passe", "🔑"), ("auth", "🔑"), ("scan", "📡"), ("balay", "📡"), ("sql", "💉"), ("inject", "💉"),
               ("xss", "🧪"), ("leurre", "🎯"), ("robot", "🤖"), ("aspir", "🕷️"), ("crawl", "🕷️"), ("form", "📝"), ("lfi", "📂"),
               ("traversal", "📂"), ("rce", "💣"), ("faille", "🐛"), ("cve", "🐛"))


def icone_categorie(cat: Any) -> str:
    c = str(cat or "").lower()
    return next((e for k, e in _ICONES_CAT if k in c), "🛡️")


def drapeau(cc: Any) -> Optional[str]:
    """Le drapeau d'un code pays ISO à deux lettres (indicateurs régionaux) ; None pour « autres » ou un code invalide."""
    c = str(cc or "")
    return "".join(chr(0x1F1E6 + ord(x) - 65) for x in c) if len(c) == 2 and c.isascii() and c.isalpha() and c.isupper() else None


def emoji_png(e: str) -> Optional[bytes]:
    if e in _EMOJIS:
        return _EMOJIS[e]
    png = None
    try:
        import io
        from PIL import Image, ImageDraw, ImageFont
        f = ImageFont.truetype(str(EMOJI_POLICE), 109)
        im = Image.new("RGBA", (160, 160), (255, 255, 255, 0))
        ImageDraw.Draw(im).text((10, 10), e, font=f, embedded_color=True)
        bb = im.getbbox()
        if bb:
            t = io.BytesIO()
            im.crop(bb).save(t, format="PNG")
            png = t.getvalue()
    except (ImportError, OSError, ValueError):
        png = None
    _EMOJIS[e] = png
    return png


# ── mise en page (fpdf2, A4 paysage, papier) ──────────────────────────────
def T(v: Any) -> str:
    """Le texte écrit dans le PDF : adresses masquées, puis latin-1 de la police de base (comme pdf_aurora)."""
    import pdf_aurora as A
    return A.txt(sans_ip(str(v)))


class _Doc:
    """Les primitives de la version papier ; une instance par PDF."""

    def __init__(self, data: dict):
        from fpdf import FPDF
        self.d = data
        self.pdf = FPDF(orientation="L", unit="mm", format="A4")
        self.pdf.set_auto_page_break(False)
        self.pdf.set_margins(14, 12, 14)
        self.n = 0

    # texte
    def ecrit(self, x, y, w, h, texte, taille=9.0, gras=False, coul=TEXTE, align="L"):
        p = self.pdf
        p.set_font("Helvetica", "B" if gras else "", taille)
        p.set_text_color(*coul)
        p.set_xy(x, y)
        p.cell(w, h, T(texte), align=align)

    def para(self, x, y, w, texte, taille=9.0, coul=DOUX, gras=False, interligne=1.38) -> float:
        p = self.pdf
        p.set_font("Helvetica", "B" if gras else "", taille)
        p.set_text_color(*coul)
        p.set_xy(x, y)
        p.multi_cell(w, taille * 0.3528 * interligne, T(texte), align="L")
        return p.get_y()

    def court(self, texte, w, taille) -> str:
        """Le texte coupé pour tenir dans `w` mm (point final si coupé)."""
        p = self.pdf
        p.set_font("Helvetica", "", taille)
        t = T(texte)
        if p.get_string_width(t) <= w:
            return t
        while t and p.get_string_width(t + ".") > w:
            t = t[:-1]
        return t + "."

    def filet(self, x1, y, x2):
        self.pdf.set_draw_color(*TRAIT)
        self.pdf.set_line_width(0.25)
        self.pdf.line(x1, y, x2, y)

    def icone(self, x, y, h, e) -> float:
        """Pose l'emoji `e` (hauteur `h` mm) ; rend la largeur occupée (0 si la police couleur manque)."""
        png = emoji_png(e) if e else None
        if not png:
            return 0.0
        import io
        import struct
        lg, ht = struct.unpack(">II", png[16:24])
        w = h * lg / ht if ht else h
        self.pdf.image(io.BytesIO(png), x=x, y=y, h=h)
        return w + 1.2

    def pastille(self, x, y, texte, coul, taille=7.5, emoji=None):
        p = self.pdf
        p.set_font("Helvetica", "", taille)
        ic = 4.4 if emoji and emoji_png(emoji) else 0
        w = p.get_string_width(T(texte)) + 5 + ic
        p.set_draw_color(*coul)
        p.set_line_width(0.35)
        p.rect(x, y, w, 5, style="D", round_corners=True, corner_radius=1.2)
        if ic:
            self.icone(x + 1.6, y + 0.9, 3.2, emoji)
        self.ecrit(x + ic, y, w - ic, 5, texte, taille, coul=TEXTE, align="C")
        return w

    def carte(self, x, y, ech, points, anneau=True, drapeaux=6, lignes=(3, 52)):
        """Carte du monde papier : continents en aplat (cases pleines de la grille 120 × 60 de carte_monde), un cercle par pays
        (surface proportionnelle à la valeur), anneau rouge = part bloquée, drapeau des plus gros. points : [(code, valeur, part%|None)]."""
        import carte_monde as cm
        p = self.pdf
        l0, l1 = lignes
        p.set_fill_color(214, 222, 235)
        for gx, gy in cm.points_terre():
            if l0 <= gy <= l1:
                p.rect(x + (gx - 0.5) * ech, y + (gy - 0.5 - l0) * ech, ech + 0.02, ech + 0.02, "F")
        pts = [(c, v, f) for c, v, f in points if c in cm.CENTRE and v]
        if not pts:
            return
        fort = max(v for _, v, _ in pts)
        rmax = ech * 4.6
        for rang, (c, v, f) in enumerate(sorted(pts, key=lambda t: -t[1])):
            lat, lon = cm.CENTRE[c]
            cx, cy = x + (lon + 180) / 3 * ech, y + ((90 - lat) / 3 - l0) * ech
            r = max(ech * 0.7, rmax * math.sqrt(v / fort))
            with p.local_context(fill_opacity=0.7):
                p.set_fill_color(*C1)
                p.circle(x=cx, y=cy, radius=r, style="F")
            if anneau and f:
                k = min(1.0, f / 100.0)
                arc = [(cx + (r + 0.8) * math.sin(2 * math.pi * k * t / 48), cy - (r + 0.8) * math.cos(2 * math.pi * k * t / 48)) for t in range(49)]
                p.set_draw_color(*C4)
                p.set_line_width(max(0.5, ech * 0.5))
                p.polyline(arc)
                p.set_line_width(0.25)
            if rang < drapeaux and drapeau(c):
                self.icone(cx - ech * 1.4, cy - ech * 1.0, ech * 2.0, drapeau(c))

    # feuille
    def feuille(self, titre, sous, grand=False):
        p = self.pdf
        p.add_page()
        self.n += 1
        p.set_fill_color(*BLANC)
        p.rect(0, 0, 297, 210, "F")
        y = 13
        if self.d.get("exemple"):
            p.set_font("Helvetica", "", 7.5)
            w = p.get_string_width(T("Données d'exemple")) + 6
            self.pastille(283 - w, 12, "Données d'exemple", C2)
        taille = 21 if grand else 17
        p.set_font("Helvetica", "B", taille)
        p.set_text_color(*TEXTE)
        p.set_xy(14, y)
        p.multi_cell(240, taille * 0.3528 * 1.18, T(titre), align="L")
        y = p.get_y() + 1.5
        if sous:
            y = self.para(14, y, 235, sous, 9.5) + 1
        cur = self.d["jours"]
        self.filet(14, 196, 283)
        self.ecrit(14, 197.5, 180, 5, f"SecuBox, rapport de pilotage, semaine {libelle_periode(cur)}", 7.5, coul=DOUX)
        self.ecrit(150, 197.5, 100, 5, "Données réelles : « non mesuré » quand une mesure manque", 7.5, coul=DOUX, align="R")
        self.ecrit(253, 197.5, 30, 5, f"{self.n} / 6", 7.5, coul=DOUX, align="R")
        return y + 3

    # graphiques
    def mini_serie(self, x, y, w, h, s, coul, resserre=False, etiquettes=None):
        """Une barre par jour ; jour non mesuré : un trait bas, en pointillés (jamais une barre à 0)."""
        p = self.pdf
        vals = [v for v in s if v is not None]
        n = len(s)
        pas = w / max(1, n)
        bw = pas * 0.72
        if vals:
            hi = max(vals)
            lo = min(vals) - (hi - min(vals)) * 0.25 if resserre else 0.0
            if resserre and hi == lo:
                lo = hi - 1
            for i, v in enumerate(s):
                bx = x + i * pas + (pas - bw) / 2
                if v is None:
                    p.set_draw_color(*TRAIT)
                    p.set_dash_pattern(dash=0.6, gap=0.6)
                    p.line(bx, y + h - 0.3, bx + bw, y + h - 0.3)
                    p.set_dash_pattern()
                    continue
                bh = max(0.5, (v - lo) / (hi - lo) * h) if hi > lo else (h * 0.6 if hi > 0 else 0.5)
                fort = (i == n - 1) or v == hi
                with p.local_context(fill_opacity=1.0 if fort else 0.5):
                    p.set_fill_color(*coul)
                    p.rect(bx, y + h - bh, bw, bh, "F")
        else:
            self.ecrit(x, y + h / 2 - 2.5, w, 5, "aucune série mesurée", 7.5, coul=DOUX, align="C")
        if etiquettes:
            for i, e in enumerate(etiquettes):
                self.ecrit(x + i * pas, y + h + 0.6, pas, 3.5, e, 6.2, coul=DOUX, align="C")

    def barres(self, x, y, w, lignes, couleur=C1, pas=7.2, lw_part=0.38, vw=24, icone=None):
        """Lignes « nom · barre · valeur » ; une valeur None s'écrit « non mesuré », sans barre."""
        p = self.pdf
        vals = [lg[1] for lg in lignes if lg[1] is not None]
        fort = max(vals) if vals else 0
        lw = w * lw_part
        bw = w - lw - vw - 3
        for lg in lignes:
            nom, v = lg[0], lg[1]
            txtv = lg[2] if len(lg) > 2 and lg[2] is not None else fn(v)
            c = lg[3] if len(lg) > 3 else couleur
            ic = self.icone(x, y + 0.6, 3.8, icone(nom)) if icone else 0.0
            self.ecrit(x + ic, y, lw - 1 - ic, 5, self.court(nom, lw - 2 - ic, 8.5), 8.5)
            p.set_fill_color(*CREUX)
            p.rect(x + lw, y + 1.2, bw, 3, "F")
            if v is not None and fort > 0:
                p.set_fill_color(*c)
                p.rect(x + lw, y + 1.2, max(0.6, bw * v / fort), 3, "F")
            self.ecrit(x + lw + bw + 1, y, vw + 2, 5, txtv, 8.5, gras=v is not None, coul=TEXTE if v is not None else DOUX, align="R")
            y += pas
        return y

    def rien(self, x, y, w, texte):
        self.ecrit(x, y, w, 5, texte, 8.5, coul=DOUX)
        return y + 7


# ── les six feuilles ──────────────────────────────────────────────────────
def _f1(D: _Doc, ks: list[dict], decs: list[dict]) -> None:
    d = D.d
    y = D.feuille(verdict(d, ks, decs), f"Votre relais SecuBox, semaine {libelle_periode(d['jours'])}. Sept jours de service, de trafic "
                  "et de défense, comparés aux sept précédents quand ceux-ci sont mesurés. " + manques(ks), grand=True)
    y = max(y, 52)
    cw, ch = 189 / 3, 64
    for i, k in enumerate(ks):
        cx, cy = 14 + (i % 3) * cw, y + (i // 3) * ch
        D.filet(cx, cy, cx + cw - 4)
        ic = D.icone(cx, cy + 2.6, 3.8, ICONES_KPI.get(k["cle"]))
        D.ecrit(cx + ic, cy + 2, cw - 6 - ic, 5, k["libelle"], 9, coul=DOUX)
        D.ecrit(cx, cy + 8, cw - 6, 10, k["texte"], 20 if k["valeur"] is not None else 15, gras=True, coul=TEXTE if k["valeur"] is not None else DOUX)
        e = k["ecart"]
        coul = DOUX
        if e and k["sens"] and e[1]:
            coul = OK if e[1] * k["sens"] > 0 else C4
        D.ecrit(cx, cy + 19, cw - 6, 5, D.court(k["sous"], cw - 8, 8.5), 8.5, coul=coul)
        D.ecrit(cx, cy + 24, cw - 6, 4, D.court(k["definition"], cw - 8, 7), 7, coul=DOUX)
        D.mini_serie(cx, cy + 30, cw - 10, 24, k["serie"], k["couleur"], resserre=(k["cle"] == "dispo"),
                     etiquettes=[jour_court(j).split()[0][0].upper() + jour_court(j).split()[1] for j in d["jours"]])
    xm = 14 + 189 + 4
    D.filet(xm, y, 283)
    D.icone(xm, y + 2.6, 3.8, "🌍")
    D.ecrit(xm + 5, y + 2, 72, 5, "Origines des requêtes hostiles", 9, coul=DOUX)
    ps, kp = pays(d)
    D.carte(xm, y + 12, 76 / 120, [(x["code"], x["hostiles"], x["part"]) for x in ps], drapeaux=4)
    if ps:
        yy = y + 46
        for x in ps[:5]:
            ic = D.icone(xm, yy + 0.7, 3.4, drapeau(x["code"]))
            D.ecrit(xm + ic, yy, 46 - ic, 5, D.court(x["nom"], 44 - ic, 8.2), 8.2)
            D.ecrit(xm + 44, yy, 32, 5, f"{fn(x['bloquees'])} bloquées", 8.2, align="R")
            yy += 5.6
        D.para(xm, yy + 1, 76, "Cercle : requêtes hostiles ; anneau rouge : part bloquée. Détail en feuille 3.", 7)
    else:
        D.rien(xm, y + 48, 76, f"Pays : {NON_MESURE}")
    yb = y + 2 * ch + 2
    ab = absentes(d)
    D.para(14, yb, 269, ("Mesures absentes cette semaine : " + " ; ".join(ab) + ".") if ab else "Toutes les mesures de la semaine sont présentes.", 7.8)


def _f2(D: _Doc) -> None:
    d = D.d
    cs = couches(d)
    y = D.feuille("Le trafic, couche par couche", "Requêtes par jour. Visiteurs et robots déclarés : journaux nginx (ce que les sites ont "
                  "servi) ; détournées et bloquées : WAF (jamais servies). Les adresses déjà bannies au pare-feu ne sont plus comptées.")
    coul = {"Visiteurs": C1, "Robots déclarés": C2, "Détournées (leurres)": C3, "Bloquées": C4}
    x0, w, h = 30, 140, 112
    yb = y + 8 + h
    lx = 14
    for nom, c in coul.items():
        D.pdf.set_fill_color(*c)
        D.pdf.rect(lx, y + 1, 3, 3, "F")
        ic = D.icone(lx + 4, y + 0.6, 3.6, ICONES_COUCHE.get(nom))
        D.ecrit(lx + 4 + ic, y, 40, 5, nom, 8.2)
        D.pdf.set_font("Helvetica", "", 8.2)
        lx += D.pdf.get_string_width(T(nom)) + 10 + ic
    tots = []
    for i in range(7):
        vs = [cs[k][i] for k in cs]
        tots.append(sum(v for v in vs if v is not None) if any(v is not None for v in vs) else None)
    hi = max([t for t in tots if t is not None] or [0])
    if hi > 0:
        pas_y = 10 ** max(0, int(math.log10(hi)))
        while hi / pas_y > 6:
            pas_y *= 2
        haut = math.ceil(hi / pas_y) * pas_y
        p = D.pdf
        for g in range(0, int(haut) + 1, int(pas_y)):
            gy = yb - g / haut * h
            D.filet(x0, gy, x0 + w)
            D.ecrit(14, gy - 2.5, x0 - 16, 5, fn(g), 7, coul=DOUX, align="R")
        cw = w / 7
        for i, j in enumerate(d["jours"]):
            bas = yb
            partiel = False
            for k in cs:
                v = cs[k][i]
                if v is None:
                    partiel = True
                    continue
                bh = v / haut * h
                p.set_fill_color(*coul[k])
                with p.local_context(fill_opacity=0.88):
                    p.rect(x0 + i * cw + cw * 0.18, bas - bh, cw * 0.64, bh, "F")
                bas -= bh
            D.ecrit(x0 + i * cw, yb + 1, cw, 4, jour_court(j), 7.5, coul=DOUX, align="C")
            if partiel:
                D.ecrit(x0 + i * cw, yb + 4.5, cw, 4, "partiel", 6.5, coul=C4, align="C")
        pk = pic(cs["Bloquées"], d["jours"])
        if pk:
            D.para(x0, yb + 10, w, f"Pic le {jour_court(pk['jour'])} : {fn(pk['valeur'])} requêtes bloquées, {fd(pk['facteur'], 1)} fois la médiane "
                   "des autres jours.", 8.2, coul=TEXTE)
    else:
        D.rien(x0, y + 40, w, "Aucune couche mesurée cette semaine.")
    xr, wr = 185, 98
    D.ecrit(xr, y, wr, 5, "Part de chaque couche sur la semaine", 9.5, gras=True)
    pr = parts(cs)
    yy = D.barres(xr, y + 7, wr, [(k, v, t, coul[k]) for k, v, t in pr], lw_part=0.42, vw=34, icone=ICONES_COUCHE.get)
    if any(v is None for _, v, _ in pr):
        yy = D.para(xr, yy, wr, "Une part n'est donnée que si les quatre couches sont mesurées les sept jours ; sinon le total de la "
                    "semaine, ou les jours qui manquent.", 7.5)
    yy += 5
    sites, k = RQ_cumul_sites(d)
    D.ecrit(xr, yy, wr, 5, "Requêtes servies par site" + (f" ({k} {pl(k, 'jour mesuré', 'jours mesurés')} sur 7)" if k < 7 else ""), 9.5, gras=True)
    lignes = sorted(sites.items(), key=lambda kv: -kv[1])[:6]
    if lignes:
        D.barres(xr, yy + 7, wr, [(s, n) for s, n in lignes], C1)
    else:
        D.rien(xr, yy + 7, wr, NON_MESURE)


def RQ_cumul_sites(d: dict) -> tuple[dict, int]:
    return cumul_dict(d, d["jours"], ("nginx", "par_site"))


def _f3(D: _Doc) -> None:
    d = D.d
    ps, k = pays(d)
    y = D.feuille("D'où viennent les requêtes hostiles", "Surface du cercle : requêtes hostiles vues par le WAF. Anneau rouge : part "
                  "bloquée. Pays déduit de l'adresse par la base GeoLite2 de la box ; les réseaux locaux ne sont pas placés.")
    import carte_monde as cm
    ech = 1.58                              # la grille 120 × 60 de carte_monde, à 1,58 mm la case (lignes 3 à 52 dessinées)
    x0, y0 = 14, y + max(4.0, (190 - y - 49 * ech - 12) / 2)
    D.carte(x0, y0, ech, [(x["code"], x["hostiles"], x["part"]) for x in ps])
    if not ps:
        D.rien(x0 + 50, y0 + 35, 110, f"Pays des requêtes hostiles : {NON_MESURE} (base GeoIP absente ou journal illisible).")
    if ps:
        fort = max(x["hostiles"] for x in ps)
        hors = sum(1 for x in ps if x["code"] not in cm.CENTRE)
        D.para(x0, y0 + 49 * ech + 3, 188, f"Le plus grand cercle : {fn(fort)} {pl(fort, 'requête hostile', 'requêtes hostiles')} sur la période. "
               f"{len(ps)} {pl(len(ps), 'pays identifié', 'pays identifiés')}" + (f", dont {hors} sans position sur la carte." if hors else "."), 7.8)
    xr, wr = 206, 77
    D.ecrit(xr, y, wr, 5, "Pays, par volume bloqué" + (f" ({k} {pl(k, 'jour mesuré', 'jours mesurés')} sur 7)" if 0 < k < 7 else ""), 9.5, gras=True)
    yy = y + 8
    cols = ((0, 31, "Pays", "L"), (31, 16, "Hostiles", "R"), (47, 17, "Bloquées", "R"), (64, 13, "Part", "R"))
    for dx, w, t, a in cols:
        D.ecrit(xr + dx, yy, w, 5, t, 8, coul=DOUX, align=a)
    yy += 6
    D.filet(xr, yy, xr + wr)
    for x in ps[:12]:
        ic = D.icone(xr, yy + 1.5, 3.4, drapeau(x["code"]))
        vals = (D.court(x["nom"], 30 - ic, 8.5), fn(x["hostiles"]), fn(x["bloquees"]), fpct(x["part"], 0))
        for i, ((dx, w, _, a), v) in enumerate(zip(cols, vals)):
            if i == 0:
                dx, w = dx + ic, w - ic
            D.ecrit(xr + dx, yy + 0.8, w, 5, v, 8.5, align=a)
        yy += 6.6
        D.filet(xr, yy, xr + wr)
    if not ps:
        D.rien(xr, yy + 2, wr, NON_MESURE)


def _f4(D: _Doc, ks: list[dict]) -> None:
    d = D.d
    K = {k["cle"]: k for k in ks}
    y = D.feuille("La défense, du premier signe au blocage", "Chaque requête hostile reconnue par le WAF est arrêtée, refusée, détournée "
                  "vers un leurre ou laissée passer sous surveillance ; une adresse qui insiste est mise au ban.")
    cur = d["jours"]
    hostiles = somme(serie(d, cur, lambda r: _v(r, "waf", "hostiles")))
    servies = K["servies"]["valeur"]
    vues = (servies + K["bloquees"]["valeur"] + somme(serie(d, cur, lambda r: _v(r, "waf", "couches", "detourne")))) if (servies is not None and K["bloquees"]["valeur"] is not None) else None
    D.ecrit(14, y, 125, 5, "De la requête au bannissement", 9.5, gras=True)
    yy = D.barres(14, y + 7, 125, [("Requêtes reçues", vues, None, C1), ("Requêtes hostiles reconnues", hostiles, None, C3),
                                   ("Requêtes bloquées", K["bloquees"]["valeur"], None, C4), ("Bans posés", K["bans"]["valeur"], None, C4)], pas=8, icone=ICONES_COUCHE.get)
    D.para(14, yy, 125, "Reçues = servies par nginx + bloquées + détournées. Les bans comptent des adresses, pas des requêtes.", 7.5)
    yy += 12
    cats, k = cumul_dict(d, cur, ("waf", "categories"))
    fr: dict = {}
    for c, n in cats.items():
        fr[libelle_categorie(c)] = fr.get(libelle_categorie(c), 0) + n
    cats = fr
    D.ecrit(14, yy, 125, 5, "Ce qui a été bloqué" + (f" ({k} {pl(k, 'jour mesuré', 'jours mesurés')} sur 7)" if 0 < k < 7 else ""), 9.5, gras=True)
    top = sorted(cats.items(), key=lambda kv: -kv[1])[:6]
    yy = D.barres(14, yy + 7, 125, [(c, n) for c, n in top], C4, pas=7, icone=icone_categorie) if top else D.rien(14, yy + 7, 125, NON_MESURE)
    yy += 4
    D.ecrit(14, yy, 125, 5, "Ce que le WAF a fait des requêtes hostiles", 9.5, gras=True)
    rep_ = [(lib, somme(serie(d, cur, lambda r, c=c: _v(r, "waf", "couches", c))), None, col) for lib, c, col in
           (("Arrêtées (adresse au ban)", "arrete", C4), ("Refusées", "refuse", C4), ("Détournées vers un leurre", "detourne", C3),
            ("Laissées passer, surveillées", "passe", C2))]
    D.barres(14, yy + 7, 125, rep_, C4, pas=7, icone=ICONES_COUCHE.get)
    xr, wr = 152, 131
    D.ecrit(xr, y, wr, 5, "Quand ? Requêtes bloquées par jour et par heure (Paris)", 9.5, gras=True)
    ch = chaleur(d)
    vals = [v for ligne in ch if ligne for v in ligne]
    hi = max(vals) if vals else 0
    cw, rh = (wr - 16) / 24, 15.5
    p = D.pdf
    for i, ligne in enumerate(ch):
        ry = y + 8 + i * (rh + 1.4)
        D.ecrit(xr, ry + rh / 2 - 2.5, 15, 5, jour_court(cur[i]), 7.5, coul=DOUX)
        for hcol in range(24):
            rx = xr + 16 + hcol * cw
            if ligne is None:
                p.set_draw_color(*TRAIT)
                p.rect(rx + 0.2, ry, cw - 0.4, rh, "D")
                continue
            q = ligne[hcol] if hcol < len(ligne) else 0
            with p.local_context(fill_opacity=0.06 + 0.94 * ((q / hi) ** 1.2 if hi else 0)):
                p.set_fill_color(*C4)
                p.rect(rx + 0.2, ry, cw - 0.4, rh, "F")
        if ligne is None:
            D.ecrit(xr + 16, ry + rh / 2 - 2.5, wr - 16, 5, NON_MESURE, 7.5, coul=DOUX, align="C")
    yl = y + 8 + 7 * (rh + 1.4)
    for hcol in (0, 6, 12, 18, 23):
        D.ecrit(xr + 16 + hcol * cw - 3, yl, cw + 6, 4, f"{hcol} h", 7, coul=DOUX, align="C")
    if hi:
        D.ecrit(xr, yl + 5, wr, 4, f"Teinte la plus forte : {fn(hi)} {pl(hi, 'requête bloquée', 'requêtes bloquées')} dans l'heure.", 7.5, coul=DOUX)


def _f5(D: _Doc) -> None:
    d = D.d
    inst = d.get("instant") or {}
    act = inst.get("acteurs")
    y = D.feuille("Les acteurs suivis", "Un acteur regroupe les adresses d'un même comportement (corrélation, pas attribution). Les acteurs "
                  "sont nommés par lettre : aucun identifiant ni adresse ne sort du relais.")
    cols = ((0, 24, "Acteur", "L"), (24, 70, "Comportement", "L"), (94, 22, "Décision proposée", "L"), (118, 15, "Risque", "R"),
            (135, 20, "Adresses", "R"), (157, 15, "Bans", "R"), (176, 50, "Activité par jour (UTC)", "L"), (230, 39, "État", "L"))
    x0 = 14
    for dx, w, t, a in cols:
        D.ecrit(x0 + dx, y, w, 5, t, 8, coul=DOUX, align=a)
    yy = y + 6
    D.filet(x0, yy, 283)
    if not act:
        D.rien(x0, yy + 3, 200, f"Acteurs suivis : {NON_MESURE} (Actor Intelligence ne répond pas).")
        yy += 12
    else:
        for i, a in enumerate((act.get("acteurs") or [])[:6]):
            ry = yy + 1.5
            comp = a.get("scenario") or ", ".join(a.get("tags") or []) or "comportement non qualifié"
            m = a.get("mesure")
            if m:
                reste = m.get("reste_s")
                etat = MESURE_FR.get(str(m.get("niveau")), str(m.get("niveau"))) + (f", encore {_duree(reste)}" if reste else "")
                ce = OK
            elif a.get("niveau") == "BLOCK":
                etat, ce = "À décider", C4
            else:
                etat, ce = "Observé", C3
            vals = (lettre(i), D.court(comp, 68, 8.5), NIVEAU_FR.get(str(a.get("niveau")), "—"), fn(a.get("risque")),
                    fn(a.get("adresses")), fn(a.get("bans")))
            for (dx, w, _, al), v in zip(cols[:6], vals):
                D.ecrit(x0 + dx, ry + 2, w, 5, v, 8.5, gras=dx == 0, align=al, coul=TEXTE if v != NON_MESURE else DOUX)
            D.mini_serie(x0 + 176, ry, 48, 9, serie_acteur(a, d["jours"]), C4 if a.get("niveau") == "BLOCK" else C2 if a.get("niveau") == "MITIGATE" else C3)
            D.pastille(x0 + 230, ry + 2, etat, ce, 7.5, emoji=ICONES_ETAT.get(etat.split(",")[0]))
            yy += 12
            D.filet(x0, yy, 283)
        n = act.get("suivis") or 0
        D.para(x0, yy + 2, 269, f"{n} {pl(n, 'acteur suivi', 'acteurs suivis')} au radar au moment du rapport ; les six plus risqués sont montrés. "
               "« À décider » : un blocage proposé sans mesure en cours, repris en dernière feuille. Les réseaux locaux, le maillage et la liste "
               "blanche ne sont jamais bannis.", 7.8)
        yy += 14
    pops = (inst.get("populations") or {}).get("populations")
    D.ecrit(x0, yy + 2, 269, 5, "Populations d'attaquants (7 derniers jours, au moment du rapport)", 9.5, gras=True)
    yy += 9
    if not isinstance(pops, list):
        D.rien(x0, yy, 200, NON_MESURE)
        return
    if not pops:
        D.rien(x0, yy, 200, "Aucune population d'attaquants sur 7 jours.")
        return
    tops = sorted(pops, key=lambda q: -(q.get("adresses") or 0))[:3]
    for i, pp in enumerate(tops):
        cx = x0 + i * 62
        ic = D.icone(cx, yy + 0.6, 3.8, "🔁" if pp.get("rotation") else "🎯")
        D.ecrit(cx + ic, yy, 58 - ic, 5, f"{FAMILLE_FR.get(pp.get('famille'), pp.get('famille') or '?')} : {D.court(pp.get('nom_cible') or '', 30, 8.5)}", 8.5, gras=True)
        D.ecrit(cx, yy + 5, 64, 5, f"{compte(pp.get('adresses'), 'adresse', 'adresses')}" + (", en rotation" if pp.get("rotation") else ""), 8, coul=DOUX)
        s = pp.get("serie") if isinstance(pp.get("serie"), list) else []
        D.mini_serie(cx, yy + 11, 52, 12, [v if isinstance(v, (int, float)) else None for v in s[-7:]], C3)
    pts = pays_populations(pops)
    xm = x0 + 3 * 62 + 4
    D.icone(xm, yy - 8.4, 3.8, "🌍")
    D.ecrit(xm + 5, yy - 9, 78, 5, "Pays des adresses des populations", 8.5, gras=True)
    if pts:
        D.carte(xm, yy - 2, 79 / 120, [(c, v, None) for c, v in pts], anneau=False, drapeaux=4)
        D.para(xm, yy + 31, 79, "Adresses × part du pays déclarée par chaque population (trois premiers pays).", 7)
    else:
        D.rien(xm, yy + 10, 79, f"Pays : {NON_MESURE}")


def pays_populations(pops: list) -> list[tuple[str, float]]:
    """Adresses par pays d'après les parts `pays_top` [[code, %]] de chaque population (au plus trois pays chacune)."""
    t: dict = {}
    for pp in pops or []:
        n = pp.get("adresses") if isinstance(pp, dict) else None
        if not isinstance(n, (int, float)):
            continue
        for e in pp.get("pays_top") or []:
            if isinstance(e, (list, tuple)) and len(e) == 2 and isinstance(e[1], (int, float)):
                t[str(e[0])] = t.get(str(e[0]), 0) + n * e[1] / 100.0
    return sorted(t.items(), key=lambda kv: -kv[1])


def _duree(s) -> str:
    s = int(s or 0)
    if s >= 86400:
        j = s // 86400
        return f"{j} {pl(j, 'jour', 'jours')}"
    if s >= 3600:
        return f"{s // 3600} h"
    return f"{max(1, s // 60)} min"


def serie_acteur(a: dict, jours: list[str]) -> list[Optional[float]]:
    """Activité de l'acteur aux dates de la période, d'après ses compteurs par jour UTC (`debut`, `pas`, `valeurs`) ; un jour absent
    ou nul côté actord (non mesuré) reste None."""
    j = a.get("jours")
    if not isinstance(j, dict) or not isinstance(j.get("valeurs"), list):
        return [None] * len(jours)
    if j.get("dates"):                      # jeu d'exemple : valeurs alignées sur les dates
        m = dict(zip(j["dates"], j["valeurs"][-len(j["dates"]):]))
    else:
        debut, pas = int(j.get("debut") or 0), int(j.get("pas") or 86400)
        m = {datetime.fromtimestamp(debut + i * pas, tz=timezone.utc).date().isoformat(): v for i, v in enumerate(j["valeurs"])}
    return [float(m[x]) if isinstance(m.get(x), (int, float)) else None for x in jours]


def _f6(D: _Doc, ks: list[dict], decs: list[dict]) -> None:
    d = D.d
    n = len(decs)
    y = D.feuille("Décider pour la semaine prochaine",
                  (f"{n} {pl(n, 'décision', 'décisions')}, {pl(n, 'sa raison et son effet attendu', 'leur raison et leur effet attendu')}. "
                   if n else "") + "Chaque décision naît d'un seuil écrit franchi par une mesure réelle ; rien n'est appliqué sans vous.")
    if not decs:
        D.filet(14, y, 283)
        D.ecrit(14, y + 3, 269, 7, "Rien à décider cette semaine : aucun seuil n'est franchi.", 12, gras=True)
        D.para(14, y + 11, 269, "Seuils vérifiés : service vital en échec, site injoignable, adresse proposée au ban sans suite, acteur à "
               f"bloquer sans mesure, disponibilité sous {fpct(SEUIL_DISPO, 1)}, temps de réponse médian au-dessus de {fn(SEUIL_LENT_MS)} ms, "
               f"site recevant la moitié des requêtes bloquées (au moins {fn(SEUIL_SITE_MIN)}).", 8.5)
        yy = y + 26
    else:
        yy = y
        for dc in decs:
            D.filet(14, yy, 283)
            D.pastille(14, yy + 3.5, dc["horizon"], C1, 8)
            D.ecrit(52, yy + 3, 150, 6, D.court(dc["titre"], 150, 12), 12, gras=True)
            fin = D.para(52, yy + 10, 150, dc["raison"], 8.8)
            fin2 = D.para(212, yy + 3.5, 71, dc["effet"], 8.8, coul=TEXTE)
            yy = max(fin, fin2, yy + 18) + 3
    D.filet(14, yy, 283)
    yy += 4
    K = {k["cle"]: k for k in ks}
    blocs = (("Disponibilité par jour (échelle resserrée)", K["dispo"], C1, True), ("Temps de réponse médian (ms)", K["latence"], C2, False),
             ("Bans posés par jour", K["bans"], C4, False))
    h = max(18.0, min(70.0, 183 - yy - 14))
    for i, (titre, k, c, rs) in enumerate(blocs):
        cx = 14 + i * 91
        D.ecrit(cx, yy, 85, 5, titre, 9, gras=True)
        D.ecrit(cx, yy + 5, 85, 4.5, k["texte"] if k["valeur"] is not None else k["sous"], 8, coul=DOUX)
        D.mini_serie(cx, yy + 11, 83, h, k["serie"], c, resserre=rs, etiquettes=[jour_court(j) for j in d["jours"]])
    sante = (d.get("instant") or {}).get("sante")
    ligne = (f"Contrôles de santé : {sante['ok']} sur {sante['total']} au vert le {heure_paris(sante.get('instant'))}"
             + (f" ; en échec : {', '.join(sante['vitaux_ko'])}" if sante.get("vitaux_ko") else "")
             + (f" ; avertissement : {', '.join(sante['avertissements'][:3])}" if sante.get("avertissements") else "") + ".") if sante else f"Contrôles de santé : {NON_MESURE}."
    D.para(14, min(189, yy + 11 + h + 6), 269, ligne, 7.8)


def construire_pdf(data: dict) -> bytes:
    """Le PDF complet, six feuilles A4 paysage."""
    D = _Doc(data)
    ks = kpis(data)
    decs = decisions(data, ks)
    _f1(D, ks, decs)
    _f2(D)
    _f3(D)
    _f4(D, ks)
    _f5(D)
    _f6(D, ks, decs)
    return bytes(D.pdf.output())


# ── configuration, envoi, point d'entrée ──────────────────────────────────
def config(conf: Path = CONF) -> dict:
    """`[rapport.pilotage]` : actif (faux par défaut), destinataire (à défaut celui de `[rapport.waf]`), noeud (Status Live)."""
    c = dict(DEFAUTS)
    try:
        with open(conf, "rb") as f:
            r = tomllib.load(f).get("rapport", {})
    except (OSError, ValueError):
        r = {}
    bloc = r.get("pilotage") if isinstance(r.get("pilotage"), dict) else {}
    for k in DEFAUTS:
        if k in bloc:
            c[k] = bloc[k]
    c["actif"] = c["actif"] is True
    if not c["destinataire"] and isinstance(r.get("waf"), dict):
        c["destinataire"] = str(r["waf"].get("destinataire") or "")
    return c


def executer(collecter_: Callable[[], dict], construire: Callable[[dict], bytes], envoyer: Callable[..., dict], cfg: dict) -> dict:
    if not cfg.get("actif"):
        return {"envoye": False, "raison": "désactivé : [rapport.pilotage] actif = true pour l'envoyer"}
    if "@" not in str(cfg.get("destinataire") or ""):
        return {"envoye": False, "raison": "aucun destinataire configuré ([rapport.pilotage] ou [rapport.waf])"}
    d = collecter_()
    pdf = construire(d)
    return envoyer(pdf, cfg["destinataire"], "Rapport de pilotage", "semaine",
                   objet=f"SecuBox — rapport de pilotage, semaine {libelle_periode(d['jours'])}", nom_fichier="secubox-pilotage-{date}.pdf",
                   intro="Rapport de pilotage hebdomadaire SecuBox : service, trafic, défense, acteurs et décisions.")


def main(argv: Optional[list[str]] = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    sortie, fin, exemple = None, None, False
    while args:
        a = args.pop(0)
        if a == "--sortie" and args:
            sortie = Path(args.pop(0))
        elif a == "--fin" and args:
            fin = args.pop(0)
            try:
                date.fromisoformat(fin)
            except ValueError:
                print("--fin : date AAAA-MM-JJ attendue", file=sys.stderr)
                return 2
        elif a == "--exemple":
            exemple = True
        else:
            print("usage : python3 -m api.rapport_pilotage [--sortie fichier.pdf] [--fin AAAA-MM-JJ] [--exemple]", file=sys.stderr)
            return 2
    cfg = config()
    fin = fin or RQ.hier()
    if sortie is None and not exemple:
        if not cfg["actif"]:
            print("rapport de pilotage : désactivé ([rapport.pilotage] actif = true pour l'envoyer) — rien à faire", file=sys.stderr)
            return 0
        try:
            import rapport
            res = executer(lambda: collecter(fin, noeud=cfg.get("noeud") or ""), construire_pdf, rapport.envoyer, cfg)
        except Exception as e:  # noqa: BLE001 — une tâche planifiée journalise et sort en échec
            print(f"rapport de pilotage : échec : {type(e).__name__}: {e}", file=sys.stderr)
            return 1
        print(f"rapport de pilotage : {'envoyé à ' + str(res.get('destinataire')) if res.get('envoye') else 'non envoyé (' + res.get('raison', '?') + ')'}")
        return 0
    data = donnees_exemple(fin) if exemple else collecter(fin, noeud=cfg.get("noeud") or "")
    pdf = construire_pdf(data)
    if sortie is None:
        print("--exemple sans --sortie : rien n'est envoyé ; donner --sortie fichier.pdf", file=sys.stderr)
        return 2
    sortie.write_bytes(pdf)
    print(f"rapport de pilotage : {sortie} ({len(pdf)} octets, semaine {libelle_periode(data['jours'])})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
